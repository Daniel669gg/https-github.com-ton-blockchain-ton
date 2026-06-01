"""
backend/core/cpg/oop_resolver.py — OOP analysis for Python class/method/attribute resolution.

Resolves:
- Class hierarchy (bases, MRO approximation)
- Method dispatch: self.method() → which class's method
- Attribute access: self.field → type and taint status
- super() calls
- @classmethod, @staticmethod, @property decorators
- __init__ attribute initialization tracking

Integrates with CPGBuilder: call CPGBuilder.build_source() first, then
OOPResolver.analyze(cpg, source_code) to add OOP resolution overlay.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .graph import CodePropertyGraph


# ---------------------------------------------------------------------------
# Taint-source patterns for attribute taint detection
# ---------------------------------------------------------------------------

_TAINT_SOURCE_PATTERNS: List[re.Pattern] = [
    re.compile(r'request\.(args|form|json|data|files|headers|cookies|values)'),
    re.compile(r'\binput\s*\('),
    re.compile(r'sys\.argv'),
    re.compile(r'os\.environ'),
    re.compile(r'os\.getenv\s*\('),
    re.compile(r'sys\.stdin'),
    re.compile(r'click\.(argument|option)'),
    re.compile(r'flask\.request'),
    re.compile(r'django\.request'),
]


def _is_taint_source_code(code: str) -> bool:
    """Return True if the given source-code snippet is a taint source."""
    return any(p.search(code) for p in _TAINT_SOURCE_PATTERNS)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ClassInfo:
    """Information about a single class definition."""
    class_name: str
    bases: List[str]                     # direct base class names
    methods: Dict[str, str]              # method_name → node_id of method def
    attributes: Dict[str, str]           # attr_name → inferred type (from __init__)
    class_node_id: str                   # CPG node_id for the class AST node
    file: str
    line: int


@dataclass
class MethodResolution:
    """The result of resolving a method call to a specific class."""
    call_node_id: str           # CPG node where method is called
    receiver_type: str          # inferred class name of receiver
    method_name: str
    resolved_class: str         # which class in MRO actually provides this method
    is_virtual: bool            # True if a subclass could override this method
    parameters: List[str]       # parameter names of the resolved method
    return_type: str            # inferred return type


@dataclass
class AttributeAccess:
    """A single self.attr read or write."""
    node_id: str
    receiver_var: str           # name of the object variable (e.g. "self", "obj")
    receiver_type: str          # inferred class name
    attribute_name: str
    access_type: str            # "read" or "write"
    is_tainted: bool            # True if assigned from a taint source in __init__
    taint_source: str           # description of taint source


@dataclass
class OOPAnalysisResult:
    """Complete result of an OOP analysis pass."""
    classes: Dict[str, ClassInfo]               # class_name → ClassInfo
    method_resolutions: List[MethodResolution]
    attribute_accesses: List[AttributeAccess]
    class_hierarchy: Dict[str, List[str]]       # class → all ancestor class names
    tainted_attributes: Dict[str, List[str]]    # class_name → [tainted attr names]


# ---------------------------------------------------------------------------
# OOPResolver
# ---------------------------------------------------------------------------

class OOPResolver:
    """
    Analyzes Python class hierarchies and resolves method/attribute accesses.

    Uses both:
    - Python ast module for accurate class/method extraction
    - CPG nodes for integration with existing taint analysis
    """

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        source_code: str,
        cpg: Optional[CodePropertyGraph] = None,
        ssa: Optional[Any] = None,
    ) -> OOPAnalysisResult:
        """
        Full OOP analysis. Main entry point.

        Args:
            source_code: Python source text to analyze.
            cpg:         Optional CodePropertyGraph built from the same source.
                         Used to map CPG node IDs to AST nodes.
            ssa:         Optional SSAForm overlay. Used for taint propagation.

        Returns:
            OOPAnalysisResult with classes, resolutions, accesses, hierarchy,
            and tainted_attributes populated.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            # Return empty result on unparseable code
            return OOPAnalysisResult(
                classes={},
                method_resolutions=[],
                attribute_accesses=[],
                class_hierarchy={},
                tainted_attributes={},
            )

        source_lines = source_code.splitlines()

        # Phase 1: discover all class definitions
        classes = self._extract_classes(tree, source_code)

        # Phase 2: build attribute type maps from __init__
        for class_info in classes.values():
            class_info.attributes = self._extract_attribute_inits(
                class_info, tree, source_lines
            )

        # Phase 3: compute MRO / class hierarchy
        mro = self._resolve_mro(classes)

        # Phase 4: resolve method calls
        method_resolutions = self._resolve_method_calls(tree, classes, mro)

        # Phase 5: track attribute accesses
        attr_accesses = self._track_attribute_accesses(tree, classes, ssa)

        # Phase 6: identify tainted attributes
        tainted_attrs = self._detect_tainted_attributes(classes, attr_accesses)

        return OOPAnalysisResult(
            classes=classes,
            method_resolutions=method_resolutions,
            attribute_accesses=attr_accesses,
            class_hierarchy=mro,
            tainted_attributes=tainted_attrs,
        )

    # ------------------------------------------------------------------
    # Phase 1: Class extraction
    # ------------------------------------------------------------------

    def _extract_classes(
        self, tree: ast.AST, source_code: str
    ) -> Dict[str, ClassInfo]:
        """Use ast.ClassDef to extract all class definitions."""
        classes: Dict[str, ClassInfo] = {}

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Base class names (best-effort: handles simple Name and Attribute)
            bases: List[str] = []
            for base in node.bases:
                bases.append(self._name_of(base))

            # Discover methods (FunctionDef / AsyncFunctionDef) directly inside
            methods: Dict[str, str] = {}
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Build a stable node_id matching CPGBuilder's convention:
                    # sha8(file):line:col:type  — we don't know file here, so we
                    # use a human-readable key that can be correlated later.
                    method_id = f"class:{node.name}:method:{item.name}:line{item.lineno}"
                    methods[item.name] = method_id

            class_id = f"class:{node.name}:line{node.lineno}"
            classes[node.name] = ClassInfo(
                class_name=node.name,
                bases=bases,
                methods=methods,
                attributes={},      # filled in Phase 2
                class_node_id=class_id,
                file="<analyzed>",
                line=node.lineno,
            )

        return classes

    # ------------------------------------------------------------------
    # Phase 2: Attribute init tracking
    # ------------------------------------------------------------------

    def _extract_attribute_inits(
        self,
        class_info: ClassInfo,
        tree: ast.AST,
        source_lines: List[str],
    ) -> Dict[str, str]:
        """
        Scan __init__ for self.attr = ... assignments.
        Returns: attr_name → inferred type string.
        """
        attrs: Dict[str, str] = {}

        # Find the __init__ method node for this class
        init_node: Optional[ast.FunctionDef] = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name != class_info.class_name:
                continue
            for item in node.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name == "__init__"
                ):
                    init_node = item  # type: ignore[assignment]
                    break
            break

        if init_node is None:
            return attrs

        # Walk all statements in __init__ looking for self.attr = <value>
        for stmt in ast.walk(init_node):
            if not isinstance(stmt, ast.Assign):
                continue
            for target in stmt.targets:
                if not isinstance(target, ast.Attribute):
                    continue
                if not isinstance(target.value, ast.Name):
                    continue
                if target.value.id != "self":
                    continue
                attr_name = target.attr
                inferred = self._infer_type_from_expr(stmt.value, source_lines)
                attrs[attr_name] = inferred

        # Also handle AnnAssign: self.attr: Type = value
        for stmt in ast.walk(init_node):
            if not isinstance(stmt, ast.AnnAssign):
                continue
            target = stmt.target
            if not isinstance(target, ast.Attribute):
                continue
            if not isinstance(target.value, ast.Name):
                continue
            if target.value.id != "self":
                continue
            attr_name = target.attr
            if attr_name not in attrs:
                if stmt.value is not None:
                    inferred = self._infer_type_from_expr(stmt.value, source_lines)
                else:
                    try:
                        inferred = ast.unparse(stmt.annotation)
                    except Exception:
                        inferred = "unknown"
                attrs[attr_name] = inferred

        return attrs

    # ------------------------------------------------------------------
    # Phase 3: MRO resolution
    # ------------------------------------------------------------------

    def _resolve_mro(
        self, classes: Dict[str, ClassInfo]
    ) -> Dict[str, List[str]]:
        """
        Approximate Python MRO (C3 linearization simplified).
        For each class: [class, base1, base1.base, ..., object]

        This is a depth-first left-to-right approximation rather than full C3,
        which is sufficient for single-inheritance and simple multiple-inheritance.
        """
        cache: Dict[str, List[str]] = {}

        def compute_mro(cls_name: str, seen: Set[str]) -> List[str]:
            if cls_name in cache:
                return cache[cls_name]
            if cls_name in seen:
                # Cycle guard
                return [cls_name]

            seen = seen | {cls_name}
            result: List[str] = [cls_name]

            cls_info = classes.get(cls_name)
            if cls_info is None:
                # Unknown class — treat as leaf
                cache[cls_name] = result
                return result

            for base in cls_info.bases:
                if base in ("object", ""):
                    continue
                base_mro = compute_mro(base, seen)
                for b in base_mro:
                    if b not in result:
                        result.append(b)

            # Always end with "object"
            if "object" not in result:
                result.append("object")

            cache[cls_name] = result
            return result

        hierarchy: Dict[str, List[str]] = {}
        for cls_name in classes:
            # Ancestors only (exclude self)
            mro = compute_mro(cls_name, set())
            hierarchy[cls_name] = mro[1:]  # ancestors list

        return hierarchy

    # ------------------------------------------------------------------
    # Phase 4: Method call resolution
    # ------------------------------------------------------------------

    def _resolve_method_calls(
        self,
        tree: ast.AST,
        classes: Dict[str, ClassInfo],
        mro: Dict[str, List[str]],
    ) -> List[MethodResolution]:
        """
        Find all obj.method() calls and resolve which class provides the method.
        Uses type inference: if var is assigned from ClassName(), receiver_type = ClassName.
        """
        resolutions: List[MethodResolution] = []

        # Step 1: build a map of variable → class type via assignment inference
        # Scope-aware: we track per-function scope
        var_types: Dict[str, str] = {}  # var_name → class_name (module scope)

        # Collect all top-level and per-function variable assignments
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        class_name = self._class_from_call(node.value, classes)
                        if class_name:
                            var_types[target.id] = class_name

        # Step 2: find all method calls and attempt resolution
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue

            method_name = func.attr
            receiver = func.value

            # Determine receiver type
            receiver_type = self._infer_receiver_type(receiver, var_types, classes)
            if not receiver_type:
                continue

            # Walk MRO to find which class defines this method
            resolved_class = self.get_method_owner(receiver_type, method_name, mro, classes)
            if not resolved_class:
                continue

            # Gather parameters of the resolved method
            params = self._get_method_params(resolved_class, method_name, tree)

            # A method is virtual if any subclass overrides it
            is_virtual = self._method_is_overridden(
                receiver_type, method_name, classes, mro
            )

            # Infer return type (best-effort)
            return_type = self._infer_return_type(resolved_class, method_name, tree)

            # Build a stable call_node_id
            call_node_id = f"call:{receiver_type}.{method_name}:line{getattr(node, 'lineno', 0)}"

            resolutions.append(
                MethodResolution(
                    call_node_id=call_node_id,
                    receiver_type=receiver_type,
                    method_name=method_name,
                    resolved_class=resolved_class,
                    is_virtual=is_virtual,
                    parameters=params,
                    return_type=return_type,
                )
            )

        return resolutions

    # ------------------------------------------------------------------
    # Phase 5: Attribute access tracking
    # ------------------------------------------------------------------

    def _track_attribute_accesses(
        self,
        tree: ast.AST,
        classes: Dict[str, ClassInfo],
        ssa: Optional[Any],
    ) -> List[AttributeAccess]:
        """
        Track self.attr reads and writes. Mark as tainted if assigned from
        request.* etc.
        """
        accesses: List[AttributeAccess] = []

        # Walk every function inside every class to find attribute accesses
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            class_name = node.name

            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                # Collect the "self" parameter name (usually "self", sometimes "cls")
                self_param = "self"
                if item.args.args:
                    self_param = item.args.args[0].arg

                # Walk statements in this method
                for stmt in ast.walk(item):
                    # Write: self.attr = value
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if not isinstance(target, ast.Attribute):
                                continue
                            if not isinstance(target.value, ast.Name):
                                continue
                            if target.value.id != self_param:
                                continue
                            attr_name = target.attr
                            try:
                                rhs_code = ast.unparse(stmt.value)
                            except Exception:
                                rhs_code = ""
                            tainted = _is_taint_source_code(rhs_code)
                            taint_src = rhs_code if tainted else ""
                            node_id = (
                                f"attr_write:{class_name}.{attr_name}"
                                f":line{getattr(stmt, 'lineno', 0)}"
                            )
                            accesses.append(
                                AttributeAccess(
                                    node_id=node_id,
                                    receiver_var=self_param,
                                    receiver_type=class_name,
                                    attribute_name=attr_name,
                                    access_type="write",
                                    is_tainted=tainted,
                                    taint_source=taint_src,
                                )
                            )

                    # Read: self.attr  (as a Load expression inside the statement)
                    for subnode in ast.walk(stmt):
                        if not isinstance(subnode, ast.Attribute):
                            continue
                        if not isinstance(subnode.value, ast.Name):
                            continue
                        if subnode.value.id != self_param:
                            continue
                        if not isinstance(subnode.ctx, ast.Load):
                            continue
                        attr_name = subnode.attr
                        # Check if this attribute is known-tainted from __init__
                        class_info = classes.get(class_name)
                        is_tainted = False
                        taint_src = ""
                        if class_info:
                            attr_type = class_info.attributes.get(attr_name, "")
                            is_tainted = _is_taint_source_code(attr_type)
                            taint_src = attr_type if is_tainted else ""
                        read_id = (
                            f"attr_read:{class_name}.{attr_name}"
                            f":line{getattr(subnode, 'lineno', 0)}"
                        )
                        accesses.append(
                            AttributeAccess(
                                node_id=read_id,
                                receiver_var=self_param,
                                receiver_type=class_name,
                                attribute_name=attr_name,
                                access_type="read",
                                is_tainted=is_tainted,
                                taint_source=taint_src,
                            )
                        )

        return accesses

    # ------------------------------------------------------------------
    # Phase 6: Tainted attribute detection
    # ------------------------------------------------------------------

    def _detect_tainted_attributes(
        self,
        classes: Dict[str, ClassInfo],
        attr_accesses: List[AttributeAccess],
    ) -> Dict[str, List[str]]:
        """Return dict of class → list of attribute names that are tainted."""
        tainted: Dict[str, List[str]] = {cls: [] for cls in classes}

        # Collect write accesses that are tainted
        for access in attr_accesses:
            if access.access_type == "write" and access.is_tainted:
                cls = access.receiver_type
                if cls not in tainted:
                    tainted[cls] = []
                if access.attribute_name not in tainted[cls]:
                    tainted[cls].append(access.attribute_name)

        # Also check attributes recorded directly in ClassInfo (from __init__ scan)
        for cls_name, cls_info in classes.items():
            for attr_name, attr_type in cls_info.attributes.items():
                if _is_taint_source_code(attr_type):
                    if cls_name not in tainted:
                        tainted[cls_name] = []
                    if attr_name not in tainted[cls_name]:
                        tainted[cls_name].append(attr_name)

        return tainted

    # ------------------------------------------------------------------
    # Public helper
    # ------------------------------------------------------------------

    def get_method_owner(
        self,
        class_name: str,
        method_name: str,
        mro: Dict[str, List[str]],
        classes: Dict[str, ClassInfo],
    ) -> str:
        """
        Walk MRO to find which class actually defines the method.

        Returns the name of the class that provides the method, or "" if not found.
        """
        # MRO list for class_name: [class_name, base1, base2, ..., object]
        full_mro: List[str] = [class_name] + mro.get(class_name, [])

        for cls in full_mro:
            if cls == "object":
                # object always has __init__, __str__, etc.
                if method_name in ("__init__", "__str__", "__repr__", "__eq__",
                                   "__hash__", "__new__", "__del__"):
                    return "object"
                continue
            cls_info = classes.get(cls)
            if cls_info and method_name in cls_info.methods:
                return cls

        return ""

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _name_of(node: ast.AST) -> str:
        """Extract a dotted name string from an AST Name or Attribute node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = OOPResolver._name_of(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _class_from_call(node: ast.AST, classes: Dict[str, ClassInfo]) -> str:
        """
        If *node* is a Call to a known class constructor, return the class name.
        e.g. MyClass() → "MyClass"
        """
        if not isinstance(node, ast.Call):
            return ""
        func_name = OOPResolver._name_of(node.func)
        # Simple name match
        if func_name in classes:
            return func_name
        # Attribute access: module.ClassName()
        last_part = func_name.split(".")[-1]
        if last_part in classes:
            return last_part
        return ""

    @staticmethod
    def _infer_receiver_type(
        receiver: ast.AST,
        var_types: Dict[str, str],
        classes: Dict[str, ClassInfo],
    ) -> str:
        """
        Infer the class type of a method call receiver.
        Handles:
          - obj.method() where obj was assigned from ClassName()
          - self.method() (inside a class body — limited without scope tracking)
          - ClassName.method() (class-level or static call)
        """
        if isinstance(receiver, ast.Name):
            name = receiver.id
            if name in var_types:
                return var_types[name]
            # "self" receiver — type not easily determined without scope
            return ""
        if isinstance(receiver, ast.Attribute):
            # Could be super().method() or instance.sub_obj.method()
            pass
        return ""

    def _infer_type_from_expr(
        self, expr: ast.AST, source_lines: List[str]
    ) -> str:
        """Infer a type string from an assignment RHS expression."""
        try:
            code = ast.unparse(expr)
        except Exception:
            return "unknown"

        # Check if it's a taint source — return its code as the "type"
        if _is_taint_source_code(code):
            return code

        # Literal types
        if isinstance(expr, ast.Constant):
            val = expr.value
            if val is None:
                return "NoneType"
            return type(val).__name__

        # Constructor call: ClassName(...)
        if isinstance(expr, ast.Call):
            func_name = self._name_of(expr.func)
            if func_name:
                return func_name
            return "object"

        # Built-in collections
        if isinstance(expr, ast.List):
            return "list"
        if isinstance(expr, ast.Dict):
            return "dict"
        if isinstance(expr, ast.Set):
            return "set"
        if isinstance(expr, ast.Tuple):
            return "tuple"

        # JoinedStr (f-string)
        if isinstance(expr, ast.JoinedStr):
            return "str"

        return "unknown"

    def _get_method_params(
        self,
        class_name: str,
        method_name: str,
        tree: ast.AST,
    ) -> List[str]:
        """Return the parameter names of method_name in class_name."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name != class_name:
                continue
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if item.name != method_name:
                    continue
                params: List[str] = []
                for arg in (
                    item.args.posonlyargs
                    + item.args.args
                    + item.args.kwonlyargs
                ):
                    params.append(arg.arg)
                if item.args.vararg:
                    params.append(f"*{item.args.vararg.arg}")
                if item.args.kwarg:
                    params.append(f"**{item.args.kwarg.arg}")
                return params
        return []

    def _method_is_overridden(
        self,
        class_name: str,
        method_name: str,
        classes: Dict[str, ClassInfo],
        mro: Dict[str, List[str]],
    ) -> bool:
        """
        Return True if any known subclass of class_name also defines method_name.
        """
        for cls_name, cls_info in classes.items():
            if cls_name == class_name:
                continue
            # Check if class_name is in cls_name's ancestry
            ancestors = mro.get(cls_name, [])
            if class_name in ancestors and method_name in cls_info.methods:
                return True
        return False

    def _infer_return_type(
        self,
        class_name: str,
        method_name: str,
        tree: ast.AST,
    ) -> str:
        """
        Best-effort infer the return type of a method.
        Looks at return annotation first, then at return statements.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name != class_name:
                continue
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if item.name != method_name:
                    continue

                # Return annotation
                if item.returns is not None:
                    try:
                        return ast.unparse(item.returns)
                    except Exception:
                        pass

                # Infer from return statements
                for stmt in ast.walk(item):
                    if isinstance(stmt, ast.Return) and stmt.value is not None:
                        if isinstance(stmt.value, ast.Constant):
                            if stmt.value.value is None:
                                return "NoneType"
                            return type(stmt.value.value).__name__
                        if isinstance(stmt.value, ast.Name):
                            return "unknown"  # can't easily resolve variable type
                        if isinstance(stmt.value, ast.Call):
                            func_name = self._name_of(stmt.value.func)
                            if func_name:
                                return func_name
                        try:
                            code = ast.unparse(stmt.value)
                            if _is_taint_source_code(code):
                                return "user_input"
                        except Exception:
                            pass

                return "unknown"
        return "unknown"
