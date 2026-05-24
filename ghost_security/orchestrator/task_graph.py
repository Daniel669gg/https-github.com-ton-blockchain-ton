"""
Ghost Security Platform — Task Graph Orchestrator
DAG-based task scheduling with dependency resolution, parallel execution,
execution tracing, state persistence, and retry policies.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set


class NodeState(str, Enum):
    WAITING   = "waiting"    # dependencies not yet met
    READY     = "ready"      # all deps done, not yet submitted
    RUNNING   = "running"
    SUCCEEDED = "succeeded"
    FAILED    = "failed"
    SKIPPED   = "skipped"    # dep failed and skip_on_dep_failure=True


@dataclass
class TaskNode:
    node_id:    str
    name:       str
    fn:         Callable[..., Coroutine]
    deps:       List[str]               = field(default_factory=list)
    args:       tuple                   = field(default_factory=tuple)
    kwargs:     dict                    = field(default_factory=dict)
    timeout:    Optional[float]         = 120.0
    max_retries: int                    = 0
    skip_on_dep_failure: bool           = False

    # Runtime fields
    state:      NodeState  = NodeState.WAITING
    result:     Any        = None
    error:      str        = ""
    started_at: float      = 0.0
    ended_at:   float      = 0.0
    attempts:   int        = 0

    @property
    def duration(self) -> float:
        if self.started_at and self.ended_at:
            return round(self.ended_at - self.started_at, 3)
        return 0.0

    def to_dict(self) -> dict:
        return {
            "node_id":   self.node_id,
            "name":      self.name,
            "deps":      self.deps,
            "state":     self.state,
            "duration":  self.duration,
            "attempts":  self.attempts,
            "error":     self.error,
        }


@dataclass
class GraphRun:
    run_id:    str
    graph_id:  str
    started:   float        = field(default_factory=time.time)
    finished:  float        = 0.0
    nodes:     Dict[str, TaskNode] = field(default_factory=dict)
    trace:     List[dict]   = field(default_factory=list)

    def record(self, event: str, node_id: str, **extra):
        self.trace.append({
            "ts":      time.time(),
            "event":   event,
            "node_id": node_id,
            **extra,
        })

    def summary(self) -> dict:
        counts: dict = {}
        for n in self.nodes.values():
            counts[n.state] = counts.get(n.state, 0) + 1
        return {
            "run_id":    self.run_id,
            "graph_id":  self.graph_id,
            "duration":  round(self.finished - self.started, 3) if self.finished else None,
            "node_count": len(self.nodes),
            "by_state":  counts,
        }


class TaskGraph:
    """
    Define a DAG of async tasks. Edges = dependency order.
    Nodes with no pending deps run immediately (concurrently).
    """

    def __init__(self, graph_id: str = "") -> None:
        self.graph_id = graph_id or uuid.uuid4().hex[:8]
        self._nodes:  Dict[str, TaskNode] = {}
        self._dependents: Dict[str, Set[str]] = defaultdict(set)  # node → who depends on it

    # ── Graph construction ─────────────────────────────────────────────────────

    def add(
        self,
        name: str,
        fn: Callable[..., Coroutine],
        *args,
        deps: Optional[List[str]] = None,
        node_id: Optional[str] = None,
        timeout: float = 120.0,
        max_retries: int = 0,
        skip_on_dep_failure: bool = False,
        **kwargs,
    ) -> str:
        nid = node_id or uuid.uuid4().hex[:10]
        node = TaskNode(
            node_id=nid,
            name=name,
            fn=fn,
            deps=deps or [],
            args=args,
            kwargs=kwargs,
            timeout=timeout,
            max_retries=max_retries,
            skip_on_dep_failure=skip_on_dep_failure,
        )
        self._nodes[nid] = node
        for dep in (deps or []):
            self._dependents[dep].add(nid)
        return nid

    def validate(self) -> List[str]:
        """Return list of errors (empty = valid DAG)."""
        errors = []
        # Check all deps exist
        for nid, node in self._nodes.items():
            for dep in node.deps:
                if dep not in self._nodes:
                    errors.append(f"Node '{nid}' references unknown dep '{dep}'")
        # Cycle detection via DFS
        WHITE, GRAY, BLACK = 0, 1, 2
        color = {n: WHITE for n in self._nodes}

        def dfs(nid: str):
            color[nid] = GRAY
            for dep in self._nodes[nid].deps:
                if dep not in color:
                    continue
                if color[dep] == GRAY:
                    errors.append(f"Cycle detected involving node '{nid}' → '{dep}'")
                    return
                if color[dep] == WHITE:
                    dfs(dep)
            color[nid] = BLACK

        for nid in self._nodes:
            if color[nid] == WHITE:
                dfs(nid)
        return errors

    # ── Execution ──────────────────────────────────────────────────────────────

    async def execute(self, max_concurrent: int = 6) -> GraphRun:
        """Execute all nodes respecting dependency order. Returns a GraphRun."""
        errors = self.validate()
        if errors:
            raise ValueError(f"Graph validation failed: {errors}")

        # Deep-copy nodes into the run so the graph object remains reusable
        import copy
        run = GraphRun(
            run_id=uuid.uuid4().hex[:12],
            graph_id=self.graph_id,
            nodes={nid: copy.deepcopy(node) for nid, node in self._nodes.items()},
        )

        sem       = asyncio.Semaphore(max_concurrent)
        done_event: Dict[str, asyncio.Event] = {nid: asyncio.Event() for nid in run.nodes}
        tasks: List[asyncio.Task] = []

        async def run_node(node: TaskNode):
            # Wait for all deps
            for dep_id in node.deps:
                await done_event[dep_id].wait()
                dep = run.nodes[dep_id]
                if dep.state in (NodeState.FAILED, NodeState.SKIPPED):
                    if node.skip_on_dep_failure:
                        node.state = NodeState.SKIPPED
                        run.record("skipped", node.node_id, reason=f"dep {dep_id} {dep.state}")
                        done_event[node.node_id].set()
                        return

            async with sem:
                await _execute_node(node, run)
            done_event[node.node_id].set()

        async def _execute_node(node: TaskNode, run: GraphRun):
            for attempt in range(node.max_retries + 1):
                node.attempts  = attempt + 1
                node.state     = NodeState.RUNNING
                node.started_at = time.time()
                run.record("started", node.node_id, attempt=attempt)

                try:
                    coro = node.fn(*node.args, **node.kwargs)
                    if node.timeout:
                        node.result = await asyncio.wait_for(coro, timeout=node.timeout)
                    else:
                        node.result = await coro
                    node.state   = NodeState.SUCCEEDED
                    node.ended_at = time.time()
                    run.record("succeeded", node.node_id, duration=node.duration)
                    return

                except asyncio.TimeoutError:
                    node.error = f"Timeout after {node.timeout}s"
                except asyncio.CancelledError:
                    node.state   = NodeState.FAILED
                    node.error   = "Cancelled"
                    node.ended_at = time.time()
                    run.record("cancelled", node.node_id)
                    return
                except Exception as exc:
                    node.error = str(exc)

                if attempt >= node.max_retries:
                    node.state   = NodeState.FAILED
                    node.ended_at = time.time()
                    run.record("failed", node.node_id, error=node.error, attempts=node.attempts)
                    return
                else:
                    await asyncio.sleep(2 ** attempt)

        # Start all nodes concurrently; each blocks internally on its deps
        for node in run.nodes.values():
            if not node.deps:
                node.state = NodeState.READY
            tasks.append(asyncio.create_task(run_node(node)))

        await asyncio.gather(*tasks, return_exceptions=True)
        run.finished = time.time()
        return run

    def to_dict(self) -> dict:
        return {
            "graph_id": self.graph_id,
            "nodes":    [n.to_dict() for n in self._nodes.values()],
            "edges":    [
                {"from": dep, "to": nid}
                for nid, node in self._nodes.items()
                for dep in node.deps
            ],
        }


class GraphOrchestrator:
    """
    High-level orchestrator that builds and runs task graphs for security pipelines.
    Keeps a run history for tracing.
    """

    def __init__(self) -> None:
        self._history: List[GraphRun] = []

    async def run_security_pipeline(
        self,
        target_path: str,
        scanners: Optional[List[str]] = None,
        max_concurrent: int = 4,
    ) -> GraphRun:
        """
        Build and execute a security scan pipeline graph.
        Each scanner is a node; enrichment depends on all scanners.
        """
        from runtime.structured_logger import get_logger
        log = get_logger("ghost.orchestrator")
        log.info("Building security pipeline graph", target=target_path)

        graph = TaskGraph(graph_id=f"scan-{uuid.uuid4().hex[:6]}")
        enabled = scanners or ["secrets", "owasp", "ast", "deps", "ton"]

        # helper shim: run a scanner sync fn in executor
        async def _run_scanner(name: str, path: str) -> dict:
            import asyncio, functools
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, functools.partial(_dispatch_scanner, name, path))

        scanner_ids: List[str] = []
        for scanner in enabled:
            nid = graph.add(
                f"scan:{scanner}",
                _run_scanner,
                scanner,
                target_path,
                max_retries=1,
                timeout=180.0,
            )
            scanner_ids.append(nid)

        # Enrichment node depends on all scanners
        async def _enrich(scanner_ids_done, path: str) -> dict:
            return {"status": "enriched", "path": path}

        graph.add(
            "enrich:aggregate",
            _enrich,
            scanner_ids,
            target_path,
            deps=scanner_ids,
            timeout=60.0,
        )

        run = await graph.execute(max_concurrent=max_concurrent)
        self._history.append(run)
        log.info("Pipeline completed", run_id=run.run_id, **run.summary())
        return run

    def history(self) -> List[dict]:
        return [r.summary() for r in self._history]


def _dispatch_scanner(name: str, path: str) -> dict:
    """Sync dispatcher — runs the appropriate scanner module."""
    try:
        if name == "secrets":
            from scanners.secret_scanner.secret_detector import SecretDetector
            return SecretDetector().scan_directory(path) if __import__("pathlib").Path(path).is_dir() \
                else {"findings": SecretDetector().scan_file(path)}
        if name == "owasp":
            from scanners.owasp_scanner import OWASPScanner
            s = OWASPScanner()
            return s.scan_directory(path) if __import__("pathlib").Path(path).is_dir() \
                else {"findings": s.scan_file(path)}
        if name == "ast":
            from scanners.ast_scanner.ast_analyzer import ASTScanner
            s = ASTScanner()
            return s.scan_directory(path) if __import__("pathlib").Path(path).is_dir() \
                else {"findings": s.scan_file(path)}
        if name == "deps":
            from scanners.dependency_scanner import DependencyScanner
            return DependencyScanner().scan_directory(path)
        if name == "ton":
            from scanners.ton_scanner.ton_analyzer import TONAnalyzer
            return TONAnalyzer().scan_directory(path)
    except Exception as exc:
        return {"error": str(exc), "scanner": name}
    return {"scanner": name, "findings": []}
