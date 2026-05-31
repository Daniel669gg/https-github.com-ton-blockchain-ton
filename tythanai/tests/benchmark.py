"""TythanAI — Production Benchmark v2 (real-world CVE patterns)"""
from __future__ import annotations
import os, sys, tempfile, time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

@dataclass
class BenchCase:
    name: str; language: str; code: str; expected: List[str]
    not_expected: List[str] = field(default_factory=list)
    is_safe: bool = False; source: str = ""

PYTHON_CASES = [
    BenchCase("sqli_fstring",    "py", 'db.execute(f"SELECT * FROM users WHERE id={uid}")',                ["OW-A03-001"], source="OWASP A03"),
    BenchCase("sqli_safe",       "py", 'cursor.execute("SELECT * FROM users WHERE id=%s",(uid,))',         [], is_safe=True),
    BenchCase("xss_render",      "py", 'flask.render_template_string("<b>"+name+"</b>")',                  ["OW-A03-005"], source="OWASP A03"),
    BenchCase("shell_injection", "py", 'subprocess.run(cmd, shell=True)',                                  ["OW-A03-002"], source="CWE-78"),
    BenchCase("shell_safe",      "py", 'subprocess.run(["ls","-la"], shell=False)',                        [], is_safe=True),
    BenchCase("eval_injection",  "py", 'result = eval(user_expr)',                                         ["OW-A03-004"], source="CWE-94"),
    BenchCase("md5_hash",        "py", 'digest = hashlib.md5(data).hexdigest()',                           ["OW-A02-002"], source="CWE-327"),
    BenchCase("sha256_safe",     "py", 'digest = hashlib.sha256(data).hexdigest()',                        [], is_safe=True),
    BenchCase("insecure_random", "py", 'token = random.randint(0, 2**32)',                                 ["OW-A02-004"], source="CWE-330"),
    BenchCase("secrets_safe",    "py", 'token = secrets.token_hex(32)',                                    [], is_safe=True),
    BenchCase("hardcoded_key",   "py", 'API_KEY = "sk-proj-abc123def456789012345678901234"',               ["SEC-GENERIC_API_KEY"], source="CWE-798"),
    BenchCase("env_var_safe",    "py", 'API_KEY = os.environ.get("OPENAI_API_KEY", "")',                   [], is_safe=True),
    BenchCase("debug_enabled",   "py", 'app.run(host="0.0.0.0", debug=True)',                              ["OW-A05-005"], source="OWASP A05"),
]

TON_CASES = [
    BenchCase("mode128_drain",    "fc", '() f() impure { send_raw_message(m, 128); }',                    ["TON-FUND-001"], source="Gas drain"),
    BenchCase("unauth_accept",    "fc", '() recv_external(slice s) impure { accept_message(); }',         ["TON-GAS-UNAUTH"], source="DoS"),
    BenchCase("unauth_upgrade",   "fc", '() upgrade(slice s) impure { set_code(s~load_ref()); }',        ["TON-UPG-001"], source="Takeover"),
    BenchCase("predictable_rand", "fc", 'int f() { randomize_lt(); return rand(100); }',                  ["TON-RAND-001"], source="CWE-338"),
    BenchCase("fake_jetton",      "fc", '() recv_internal(int v, cell c, slice s) impure { int op = s~load_uint(32); if (op == op::transfer_notification) { credit_user(s~load_coins()); } }', ["TON-JET-FAKE"]),
    BenchCase("safe_contract",    "fc", '() recv_internal(int v, cell c, slice s) impure { throw_unless(401, equal_slices(sender, owner)); raw_reserve(fee, 2); set_data(pack()); send_raw_message(m, 64); }', [], is_safe=True),
]

K8S_CASES = [
    BenchCase("k8s_privileged",    "yaml",
        'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n  namespace: default\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx:latest\n        securityContext:\n          privileged: true\n',
        ["K8S-POD-004"], source="CIS 5.2.1"),
    BenchCase("k8s_cluster_admin", "yaml",
        'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: dangerous\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n- kind: ServiceAccount\n  name: app\n  namespace: default\n',
        ["K8S-RBAC-001"], source="CIS 5.1.1"),
    BenchCase("k8s_safe", "yaml",
        'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n  namespace: prod\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx:1.25.3\n        securityContext:\n          privileged: false\n          runAsNonRoot: true\n          runAsUser: 1000\n          allowPrivilegeEscalation: false\n        resources:\n          limits:\n            cpu: "500m"\n            memory: "256Mi"\n',
        [], is_safe=True),
]

ALL_CASES = PYTHON_CASES + TON_CASES + K8S_CASES

def _scan_case(case):
    ext = {"py":".py","fc":".fc","yaml":".yaml","js":".js"}.get(case.language,".txt")
    fpath = ""
    t0    = time.time()
    try:
        with tempfile.NamedTemporaryFile(mode="w",suffix=ext,delete=False,encoding="utf-8") as f:
            f.write(case.code); fpath = f.name
        findings = []
        if case.language == "py":
            from scanners.owasp_scanner import OWASPScanner
            from scanners.secret_scanner.secret_detector import SecretDetector
            findings += OWASPScanner().scan_file(fpath)
            findings += SecretDetector().scan_file(fpath)
        elif case.language == "fc":
            from scanners.ton_scanner.ton_analyzer import TONAnalyzer
            findings += TONAnalyzer().analyze_file(fpath)
        elif case.language == "yaml":
            from scanners.k8s_scanner.k8s_scanner import ManifestScanner
            raw = ManifestScanner().scan_string(case.code)
            findings += [r.to_dict() if hasattr(r,"to_dict") else r for r in raw]
        ids = [f.get("id") or f.get("rule_id") or "" for f in findings]
        return ids, (time.time()-t0)*1000
    finally:
        if fpath and os.path.exists(fpath): os.unlink(fpath)

def run_benchmark(verbose=False, cases=None):
    if cases is None: cases = ALL_CASES
    print(f"\n🔬 TythanAI — Production Benchmark v2")
    print(f"   {len(cases)} cases: Python({sum(1 for c in cases if c.language=='py')}) "
          f"TON({sum(1 for c in cases if c.language=='fc')}) "
          f"K8s({sum(1 for c in cases if c.language=='yaml')})\n")
    print("=" * 66)
    results = []
    for case in cases:
        found_ids, ms = _scan_case(case)
        if case.is_safe:
            tp = fn = 0; fp = sum(1 for ne in (case.not_expected or []) if any(ne in f for f in found_ids))
            passed = fp == 0
        else:
            tp = sum(1 for exp in case.expected if any(exp in f for f in found_ids))
            fn = len(case.expected) - tp
            fp = sum(1 for ne in (case.not_expected or []) if any(ne in f for f in found_ids))
            passed = (tp == len(case.expected)) and fp == 0
        results.append((case, found_ids, tp, fn, fp, ms, passed))
        if verbose or not passed:
            tag = "SAFE" if case.is_safe else f"TP:{tp}/{len(case.expected)}"
            print(f"  {'✅' if passed else '❌'}  [{case.language:4}]  {case.name:25}  {tag:10}  {ms:5.0f}ms")
            if not passed and not case.is_safe:
                missed = [e for e in case.expected if not any(e in f for f in found_ids)]
                print(f"       ↳ missed: {missed}")

    vuln_r = [(c,f,tp,fn,fp,ms,ok) for c,f,tp,fn,fp,ms,ok in results if not c.is_safe]
    safe_r = [(c,f,tp,fn,fp,ms,ok) for c,f,tp,fn,fp,ms,ok in results if c.is_safe]
    total_exp = sum(len(c.expected) for c,*_ in vuln_r)
    total_tp  = sum(tp for _,_,tp,*_ in vuln_r)
    total_fp  = sum(fp for _,_,_,_,fp,*_ in safe_r)
    passing   = sum(1 for *_,ok in results if ok)
    recall    = total_tp / max(total_exp,1)
    precision = total_tp / max(total_tp+total_fp,1)
    f1        = 2*precision*recall/max(precision+recall,1e-9)
    avg_ms    = sum(ms for _,_,_,_,_,ms,_ in results)/max(len(results),1)

    print(); print("=" * 66)
    print(f"  Cases:      {passing}/{len(results)} passed")
    print(f"  Recall:     {recall:.1%}  ({total_tp}/{total_exp} expected found)")
    print(f"  Precision:  {precision:.1%}  ({total_fp} FP on safe cases)")
    print(f"  F1 Score:   {f1:.3f}")
    print(f"  Speed:      avg {avg_ms:.0f}ms per case")
    print()
    regressions = len(results) - passing
    if regressions:
        print(f"  ⚠ {regressions} regressions"); return 1
    print("  🎉 All cases passed!"); return 0
