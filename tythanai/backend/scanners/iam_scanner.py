"""IAM Security Scanner — cloud Identity & Access Management misconfiguration detection."""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class IAMFinding(BaseModel):
    rule_id: str
    file: str
    line: int
    severity: str
    description: str
    recommendation: str
    resource_type: str = ""  # "role" | "policy" | "user" | "group" | "service_account"
    principal: str = ""      # who is affected
    permission: str = ""     # what permission is too broad
    category: str = ""       # OVERPRIVILEGE | MISSING_MFA | PUBLIC_ACCESS | WILDCARD


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _try_parse_json(content: str) -> Optional[Dict[str, Any]]:
    """Attempt to parse content as JSON; return None on failure."""
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None


def _try_parse_yaml(content: str) -> Optional[Any]:
    """Parse YAML using only the standard library (json fallback + manual scan)."""
    # Try JSON first (valid JSON is valid YAML)
    result = _try_parse_json(content)
    if result is not None:
        return result
    # Use simple line-based YAML key extraction — no yaml library required.
    # We return None here and let callers use _yaml_lines_scan instead.
    return None


def _yaml_lines_scan(content: str) -> List[str]:
    """Return lowercased stripped lines for lightweight YAML scanning."""
    return [line.strip() for line in content.splitlines()]


def _find_line(content: str, pattern: str) -> int:
    """Return 1-based line number of first occurrence of pattern in content."""
    for i, line in enumerate(content.splitlines(), 1):
        if pattern.lower() in line.lower():
            return i
    return 1


def _json_contains_path(data: Any, path: List[str]) -> bool:
    """Walk nested dict/list looking for a key path."""
    if not path:
        return True
    if isinstance(data, dict):
        key = path[0]
        if key in data:
            return _json_contains_path(data[key], path[1:])
        for v in data.values():
            if _json_contains_path(v, path):
                return True
    elif isinstance(data, list):
        for item in data:
            if _json_contains_path(item, path):
                return True
    return False


def _iter_statements(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Yield all Statement objects from an AWS IAM policy document."""
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return stmts if isinstance(stmts, list) else []


def _action_list(action: Any) -> List[str]:
    """Normalise Action field to a list of lowercased strings."""
    if isinstance(action, str):
        return [action.lower()]
    if isinstance(action, list):
        return [a.lower() for a in action]
    return []


def _resource_list(resource: Any) -> List[str]:
    if isinstance(resource, str):
        return [resource]
    if isinstance(resource, list):
        return resource
    return []


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class IAMScanner:
    """Detect IAM misconfigurations in AWS, GCP, Azure, K8s, and Terraform files."""

    # ------------------------------------------------------------------
    # AWS IAM
    # ------------------------------------------------------------------

    def _check_aws_iam_policy(self, path: str, content: str) -> List[IAMFinding]:
        findings: List[IAMFinding] = []
        data = _try_parse_json(content)
        if data is None:
            # Try simple YAML scanning
            return self._check_aws_iam_policy_text(path, content)

        stmts = _iter_statements(data)
        for stmt in stmts:
            effect = stmt.get("Effect", "")
            actions = _action_list(stmt.get("Action", []))
            resources = _resource_list(stmt.get("Resource", []))
            principal = stmt.get("Principal", None)
            condition = stmt.get("Condition", None)
            not_principal = stmt.get("NotPrincipal", None)

            # IAM-AWS-001: wildcard action + resource + Allow
            if (
                effect == "Allow"
                and "*" in actions
                and any(r == "*" for r in resources)
            ):
                findings.append(IAMFinding(
                    rule_id="IAM-AWS-001",
                    file=path,
                    line=_find_line(content, '"Action"'),
                    severity="CRITICAL",
                    description="Wildcard IAM policy grants full admin access (Action:* on Resource:*)",
                    recommendation="Restrict actions to only those required and scope resources explicitly.",
                    permission="*",
                    category="WILDCARD",
                ))

            # IAM-AWS-002: s3:* on all resources
            if (
                effect == "Allow"
                and any("s3:*" == a for a in actions)
            ):
                for res in resources:
                    if res == "*" or res.endswith("*"):
                        findings.append(IAMFinding(
                            rule_id="IAM-AWS-002",
                            file=path,
                            line=_find_line(content, "s3:*"),
                            severity="HIGH",
                            description="Overprivileged S3 access: s3:* grants full S3 control",
                            recommendation="Restrict to specific S3 actions (s3:GetObject, s3:PutObject) on specific buckets.",
                            permission="s3:*",
                            resource_type="policy",
                            category="OVERPRIVILEGE",
                        ))
                        break

            # IAM-AWS-003: Principal:* in resource-based policy
            if principal is not None:
                is_public = (
                    principal == "*"
                    or (isinstance(principal, dict) and principal.get("AWS") == "*")
                    or (isinstance(principal, dict) and principal.get("Service") == "*")
                )
                if is_public:
                    findings.append(IAMFinding(
                        rule_id="IAM-AWS-003",
                        file=path,
                        line=_find_line(content, '"Principal"'),
                        severity="CRITICAL",
                        description="Public resource policy: Principal:* allows any entity to access this resource",
                        recommendation="Restrict Principal to specific AWS accounts, roles, or services.",
                        principal="*",
                        category="PUBLIC_ACCESS",
                    ))

            # IAM-AWS-004: iam:* allow
            if effect == "Allow" and any("iam:*" == a for a in actions):
                findings.append(IAMFinding(
                    rule_id="IAM-AWS-004",
                    file=path,
                    line=_find_line(content, "iam:*"),
                    severity="CRITICAL",
                    description="IAM admin permission grants full control over IAM resources",
                    recommendation="Grant only specific IAM actions needed (e.g., iam:GetRole).",
                    permission="iam:*",
                    resource_type="policy",
                    category="OVERPRIVILEGE",
                ))

            # IAM-AWS-005: sts:AssumeRole on *
            if (
                effect == "Allow"
                and any("sts:assumerole" == a for a in actions)
                and any(r == "*" for r in resources)
            ):
                findings.append(IAMFinding(
                    rule_id="IAM-AWS-005",
                    file=path,
                    line=_find_line(content, "AssumeRole"),
                    severity="HIGH",
                    description="Unrestricted AssumeRole: entity can assume any IAM role in any account",
                    recommendation="Restrict sts:AssumeRole to specific role ARNs.",
                    permission="sts:AssumeRole",
                    category="OVERPRIVILEGE",
                ))

            # IAM-AWS-006: NotPrincipal in Allow statement — dangerous negation
            if effect == "Allow" and not_principal is not None:
                findings.append(IAMFinding(
                    rule_id="IAM-AWS-006",
                    file=path,
                    line=_find_line(content, "NotPrincipal"),
                    severity="HIGH",
                    description="NotPrincipal in Allow statement creates dangerous negation logic that may grant unintended access",
                    recommendation="Replace NotPrincipal/Allow with explicit Deny statements.",
                    category="OVERPRIVILEGE",
                ))

            # IAM-AWS-007: Empty condition on sensitive policy
            sensitive_actions = {"iam:*", "s3:*", "*", "sts:assumerole"}
            has_sensitive = any(a in sensitive_actions for a in actions)
            if (
                effect == "Allow"
                and has_sensitive
                and condition is not None
                and isinstance(condition, dict)
                and len(condition) == 0
            ):
                findings.append(IAMFinding(
                    rule_id="IAM-AWS-007",
                    file=path,
                    line=_find_line(content, '"Condition"'),
                    severity="MEDIUM",
                    description="Missing condition constraint: empty Condition block on sensitive policy provides no access control",
                    recommendation="Add meaningful conditions (e.g., MFA required, IP restrictions, source VPC).",
                    category="MISSING_MFA",
                ))

            # IAM-AWS-008: PassRole permission
            if effect == "Allow" and any("iam:passrole" == a for a in actions):
                findings.append(IAMFinding(
                    rule_id="IAM-AWS-008",
                    file=path,
                    line=_find_line(content, "PassRole"),
                    severity="HIGH",
                    description="IAM PassRole privilege escalation risk: can assign roles to AWS services",
                    recommendation="Restrict iam:PassRole with a condition limiting which roles can be passed.",
                    permission="iam:PassRole",
                    category="OVERPRIVILEGE",
                ))

        return findings

    def _check_aws_iam_policy_text(self, path: str, content: str) -> List[IAMFinding]:
        """Fallback text-based scan for YAML IAM policies."""
        findings: List[IAMFinding] = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            low = line.lower()
            if '"action": "*"' in low or "action: '*'" in low or "action: \"*\"" in low:
                if any(
                    ('"resource": "*"' in l.lower() or "resource: '*'" in l.lower() or "resource: \"*\"" in l.lower())
                    for l in lines
                ):
                    findings.append(IAMFinding(
                        rule_id="IAM-AWS-001",
                        file=path,
                        line=i,
                        severity="CRITICAL",
                        description="Wildcard IAM policy grants full admin access (Action:* on Resource:*)",
                        recommendation="Restrict actions to only those required.",
                        permission="*",
                        category="WILDCARD",
                    ))
        return findings

    # ------------------------------------------------------------------
    # GCP IAM
    # ------------------------------------------------------------------

    def _check_gcp_iam(self, path: str, content: str) -> List[IAMFinding]:
        findings: List[IAMFinding] = []
        lines = _yaml_lines_scan(content)
        raw_lines = content.splitlines()

        for i, line in enumerate(raw_lines, 1):
            stripped = line.strip().lower()

            # IAM-GCP-001: roles/owner binding
            if "roles/owner" in stripped:
                findings.append(IAMFinding(
                    rule_id="IAM-GCP-001",
                    file=path,
                    line=i,
                    severity="CRITICAL",
                    description="Owner role assignment grants full project control",
                    recommendation="Replace roles/owner with least-privilege roles. Use roles/viewer or specific service roles.",
                    resource_type="role",
                    permission="roles/owner",
                    category="OVERPRIVILEGE",
                ))

            # IAM-GCP-002: roles/editor on service account
            if "roles/editor" in stripped:
                # look for serviceAccount in surrounding context
                ctx_start = max(0, i - 5)
                ctx_end = min(len(raw_lines), i + 5)
                ctx = "\n".join(raw_lines[ctx_start:ctx_end]).lower()
                if "serviceaccount" in ctx or "service_account" in ctx or "sa@" in ctx:
                    findings.append(IAMFinding(
                        rule_id="IAM-GCP-002",
                        file=path,
                        line=i,
                        severity="HIGH",
                        description="Editor role assigned to service account grants broad project modification rights",
                        recommendation="Replace roles/editor with specific roles for the service account's purpose.",
                        resource_type="service_account",
                        permission="roles/editor",
                        category="OVERPRIVILEGE",
                    ))

            # IAM-GCP-003: allUsers or allAuthenticatedUsers
            if "allusers" in stripped or "allauthenticatedusers" in stripped:
                findings.append(IAMFinding(
                    rule_id="IAM-GCP-003",
                    file=path,
                    line=i,
                    severity="CRITICAL",
                    description="Public IAM binding: allUsers/allAuthenticatedUsers exposes resources publicly",
                    recommendation="Remove public bindings. Restrict members to specific identities.",
                    principal="allUsers" if "allusers" in stripped else "allAuthenticatedUsers",
                    category="PUBLIC_ACCESS",
                ))

            # IAM-GCP-004: roles/iam.securityAdmin
            if "roles/iam.securityadmin" in stripped:
                findings.append(IAMFinding(
                    rule_id="IAM-GCP-004",
                    file=path,
                    line=i,
                    severity="HIGH",
                    description="Security admin role assignment grants control over IAM policies and audit configurations",
                    recommendation="Restrict roles/iam.securityAdmin to dedicated security personnel only.",
                    resource_type="role",
                    permission="roles/iam.securityAdmin",
                    category="OVERPRIVILEGE",
                ))

            # IAM-GCP-005: serviceAccountTokenCreator on service account
            if "roles/iam.serviceaccounttokencreator" in stripped:
                ctx_start = max(0, i - 8)
                ctx_end = min(len(raw_lines), i + 8)
                ctx = "\n".join(raw_lines[ctx_start:ctx_end]).lower()
                if "serviceaccount" in ctx or "service_account" in ctx:
                    findings.append(IAMFinding(
                        rule_id="IAM-GCP-005",
                        file=path,
                        line=i,
                        severity="HIGH",
                        description="Token creator role on service account allows privilege escalation via token generation",
                        recommendation="Remove serviceAccountTokenCreator role from service accounts; use Workload Identity instead.",
                        resource_type="service_account",
                        permission="roles/iam.serviceAccountTokenCreator",
                        category="OVERPRIVILEGE",
                    ))

        return findings

    # ------------------------------------------------------------------
    # Azure RBAC
    # ------------------------------------------------------------------

    def _check_azure_rbac(self, path: str, content: str) -> List[IAMFinding]:
        findings: List[IAMFinding] = []
        data = _try_parse_json(content)
        raw_lines = content.splitlines()

        if data is not None:
            findings.extend(self._check_azure_rbac_json(path, content, data))
        else:
            # Text fallback
            findings.extend(self._check_azure_rbac_text(path, content))

        return findings

    def _check_azure_rbac_json(
        self, path: str, content: str, data: Dict[str, Any]
    ) -> List[IAMFinding]:
        findings: List[IAMFinding] = []

        # Walk ARM template resources
        resources = []
        if isinstance(data, dict):
            resources = data.get("resources", [])
            if not isinstance(resources, list):
                resources = []
            # Also check if it's a standalone role assignment
            if data.get("type") == "Microsoft.Authorization/roleAssignments":
                resources = [data]

        for res in resources:
            if not isinstance(res, dict):
                continue
            if "roleAssignment" not in res.get("type", "") and "Authorization" not in res.get("type", ""):
                continue

            props = res.get("properties", {})
            if not isinstance(props, dict):
                continue

            role_def = props.get("roleDefinitionId", "")
            scope = props.get("scope", "")
            principal_type = props.get("principalType", "")

            # IAM-AZ-001: Contributor at subscription scope
            if "/contributor" in role_def.lower() or role_def.lower().endswith(
                "b24988ac-6180-42a0-ab88-20f7382dd24c"  # built-in Contributor GUID
            ):
                if "/subscriptions/" in scope.lower() and "/resourceGroups/" not in scope.lower():
                    findings.append(IAMFinding(
                        rule_id="IAM-AZ-001",
                        file=path,
                        line=_find_line(content, "Contributor"),
                        severity="CRITICAL",
                        description="Contributor role at subscription scope grants broad resource modification rights",
                        recommendation="Scope role assignments to specific resource groups or resources.",
                        resource_type="role",
                        permission="Contributor",
                        category="OVERPRIVILEGE",
                    ))

            # IAM-AZ-002: Owner role
            if "/owner" in role_def.lower() or "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" in role_def.lower():
                findings.append(IAMFinding(
                    rule_id="IAM-AZ-002",
                    file=path,
                    line=_find_line(content, "Owner"),
                    severity="CRITICAL",
                    description="Owner role assignment grants full control including the ability to assign roles",
                    recommendation="Replace Owner with specific roles. Never assign Owner broadly.",
                    resource_type="role",
                    permission="Owner",
                    category="OVERPRIVILEGE",
                ))

            # IAM-AZ-003: Managed identity with subscription-level role
            if principal_type.lower() in ("managedidentity", "serviceprincipal"):
                if "/subscriptions/" in scope.lower() and "/resourceGroups/" not in scope.lower():
                    findings.append(IAMFinding(
                        rule_id="IAM-AZ-003",
                        file=path,
                        line=_find_line(content, "principalType"),
                        severity="HIGH",
                        description="Managed identity assigned subscription-level role — over-privileged workload identity",
                        recommendation="Scope managed identity role assignments to specific resource groups.",
                        resource_type="role",
                        principal=principal_type,
                        category="OVERPRIVILEGE",
                    ))

            # IAM-AZ-004: Guest user to privileged role
            if principal_type.lower() == "guest":
                privileged = any(
                    kw in role_def.lower()
                    for kw in ("owner", "contributor", "administrator", "securityadmin")
                )
                if privileged:
                    findings.append(IAMFinding(
                        rule_id="IAM-AZ-004",
                        file=path,
                        line=_find_line(content, "Guest"),
                        severity="HIGH",
                        description="Guest user assigned to privileged role — external users should not have elevated access",
                        recommendation="Remove privileged role from guest users. Use JIT access instead.",
                        resource_type="user",
                        principal="Guest",
                        category="OVERPRIVILEGE",
                    ))

        return findings

    def _check_azure_rbac_text(self, path: str, content: str) -> List[IAMFinding]:
        """Text-based scan for ARM YAML/text files."""
        findings: List[IAMFinding] = []
        raw_lines = content.splitlines()
        for i, line in enumerate(raw_lines, 1):
            low = line.lower()
            if "contributor" in low and "roledefinitionid" in low:
                findings.append(IAMFinding(
                    rule_id="IAM-AZ-001",
                    file=path,
                    line=i,
                    severity="CRITICAL",
                    description="Contributor role at subscription scope grants broad resource modification rights",
                    recommendation="Scope role assignments to specific resource groups or resources.",
                    permission="Contributor",
                    category="OVERPRIVILEGE",
                ))
            if "owner" in low and ("roledefinitionid" in low or "role_definition_name" in low):
                findings.append(IAMFinding(
                    rule_id="IAM-AZ-002",
                    file=path,
                    line=i,
                    severity="CRITICAL",
                    description="Owner role assignment grants full control including the ability to assign roles",
                    recommendation="Replace Owner with specific roles.",
                    permission="Owner",
                    category="OVERPRIVILEGE",
                ))
        return findings

    # ------------------------------------------------------------------
    # Kubernetes RBAC
    # ------------------------------------------------------------------

    def _check_k8s_rbac(self, path: str, content: str) -> List[IAMFinding]:
        findings: List[IAMFinding] = []
        raw_lines = content.splitlines()

        # Determine overall kind
        kind = ""
        for line in raw_lines:
            m = re.match(r"^\s*kind\s*:\s*(\S+)", line)
            if m:
                kind = m.group(1)
                break

        # Parse rules blocks (ClusterRole/Role)
        if kind in ("ClusterRole", "Role"):
            findings.extend(self._check_k8s_role_rules(path, content, raw_lines, kind))

        # Parse ClusterRoleBinding / RoleBinding
        if kind in ("ClusterRoleBinding", "RoleBinding"):
            findings.extend(self._check_k8s_binding(path, content, raw_lines, kind))

        # Parse Pod / Deployment / StatefulSet for automountServiceAccountToken
        if kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            findings.extend(self._check_k8s_pod(path, content, raw_lines))

        return findings

    def _check_k8s_role_rules(
        self, path: str, content: str, raw_lines: List[str], kind: str
    ) -> List[IAMFinding]:
        findings: List[IAMFinding] = []

        # Collect all verbs and resources from rules section
        in_rules = False
        current_verbs: List[str] = []
        current_resources: List[str] = []

        def _extract_list(line: str) -> List[str]:
            """Extract items from inline YAML list like ["*", "get"] or - "*"."""
            # inline list
            m = re.search(r"\[([^\]]+)\]", line)
            if m:
                items = [s.strip().strip('"').strip("'") for s in m.group(1).split(",")]
                return [i for i in items if i]
            # dash item
            m2 = re.match(r"\s*-\s+[\"']?([^\"'\s]+)[\"']?", line)
            if m2:
                return [m2.group(1)]
            return []

        for i, line in enumerate(raw_lines, 1):
            if re.match(r"^rules\s*:", line):
                in_rules = True
            if not in_rules:
                continue

            if "verbs:" in line:
                current_verbs = _extract_list(line)
            if "resources:" in line:
                current_resources = _extract_list(line)

            # Each dash at rules level resets
            if re.match(r"\s*-\s+apiGroups:", line) or re.match(r"\s*-\s+verbs:", line):
                current_verbs = []
                current_resources = []

            # IAM-K8S-001: * verbs + * resources
            if "*" in current_verbs and "*" in current_resources:
                findings.append(IAMFinding(
                    rule_id="IAM-K8S-001",
                    file=path,
                    line=i,
                    severity="CRITICAL",
                    description=f"ClusterRole/Role with wildcard verbs and resources grants full cluster access",
                    recommendation="Replace wildcards with explicit verbs (get, list, watch) and specific resources.",
                    resource_type="role",
                    permission="*",
                    category="WILDCARD",
                ))
                # Reset to avoid duplicate findings for same rule block
                current_verbs = []
                current_resources = []
                continue

            # IAM-K8S-003: * verbs on secrets
            if "*" in current_verbs and "secrets" in current_resources:
                findings.append(IAMFinding(
                    rule_id="IAM-K8S-003",
                    file=path,
                    line=i,
                    severity="HIGH",
                    description="Wildcard verbs on secrets resource allows reading all cluster secrets",
                    recommendation="Restrict secrets verbs to get/list and limit to specific secret names.",
                    resource_type="role",
                    permission="secrets:*",
                    category="OVERPRIVILEGE",
                ))
                current_verbs = []
                current_resources = []

        return findings

    def _check_k8s_binding(
        self, path: str, content: str, raw_lines: List[str], kind: str
    ) -> List[IAMFinding]:
        findings: List[IAMFinding] = []

        # Extract roleRef name and subjects
        role_ref_name = ""
        subjects: List[Dict[str, str]] = []
        current_subject: Dict[str, str] = {}
        in_subjects = False

        for i, line in enumerate(raw_lines, 1):
            # roleRef name
            m = re.match(r"\s*name\s*:\s*(.+)$", line)
            if m:
                val = m.group(1).strip().strip('"').strip("'")
                # check context — is it roleRef.name?
                # Simpler: find 'cluster-admin' as role name
                if "cluster-admin" in val.lower():
                    role_ref_name = val

            # subjects block
            if re.match(r"^subjects\s*:", line):
                in_subjects = True
            if in_subjects:
                kind_m = re.match(r"\s*-\s*kind\s*:\s*(\S+)", line)
                if kind_m:
                    if current_subject:
                        subjects.append(current_subject)
                    current_subject = {"kind": kind_m.group(1), "line": str(i)}
                name_m = re.match(r"\s+name\s*:\s*(.+)$", line)
                if name_m and current_subject:
                    current_subject["name"] = name_m.group(1).strip().strip('"').strip("'")
                group_m = re.match(r"\s+group\s*:\s*(.+)$", line) or re.match(
                    r"\s*-\s*kind\s*:\s*Group", line
                )

        if current_subject:
            subjects.append(current_subject)

        # IAM-K8S-002: cluster-admin binding
        if role_ref_name == "cluster-admin" or "cluster-admin" in content:
            for line in raw_lines:
                if "cluster-admin" in line:
                    ln = raw_lines.index(line) + 1
                    # Check it's a roleRef, not just a comment
                    if "name" in line.lower() or "rolename" in line.lower():
                        findings.append(IAMFinding(
                            rule_id="IAM-K8S-002",
                            file=path,
                            line=ln,
                            severity="CRITICAL",
                            description="ServiceAccount/Group bound to cluster-admin ClusterRoleBinding grants full cluster control",
                            recommendation="Replace cluster-admin binding with a least-privilege ClusterRole.",
                            resource_type="role",
                            permission="cluster-admin",
                            category="WILDCARD",
                        ))
                        break

        # IAM-K8S-006: system:unauthenticated
        for i, line in enumerate(raw_lines, 1):
            if "system:unauthenticated" in line:
                findings.append(IAMFinding(
                    rule_id="IAM-K8S-006",
                    file=path,
                    line=i,
                    severity="CRITICAL",
                    description="system:unauthenticated group in RoleBinding allows unauthenticated access",
                    recommendation="Remove system:unauthenticated from all role bindings immediately.",
                    resource_type="group",
                    principal="system:unauthenticated",
                    category="PUBLIC_ACCESS",
                ))

        # IAM-K8S-005: default service account
        for i, line in enumerate(raw_lines, 1):
            low = line.strip().lower()
            if re.match(r"name\s*:\s*(default|\"default\"|'default')\s*$", low):
                ctx = "\n".join(raw_lines[max(0, i - 5):i + 3]).lower()
                if "serviceaccount" in ctx or "kind: serviceaccount" in ctx:
                    findings.append(IAMFinding(
                        rule_id="IAM-K8S-005",
                        file=path,
                        line=i,
                        severity="LOW",
                        description="Default service account used — workloads should use dedicated service accounts",
                        recommendation="Create a dedicated service account with minimal permissions for each workload.",
                        resource_type="service_account",
                        principal="default",
                        category="OVERPRIVILEGE",
                    ))

        return findings

    def _check_k8s_pod(
        self, path: str, content: str, raw_lines: List[str]
    ) -> List[IAMFinding]:
        findings: List[IAMFinding] = []

        for i, line in enumerate(raw_lines, 1):
            # IAM-K8S-004: automountServiceAccountToken: true
            if re.search(r"automountServiceAccountToken\s*:\s*true", line, re.IGNORECASE):
                findings.append(IAMFinding(
                    rule_id="IAM-K8S-004",
                    file=path,
                    line=i,
                    severity="MEDIUM",
                    description="automountServiceAccountToken: true mounts service account credentials into pod",
                    recommendation="Set automountServiceAccountToken: false unless the pod requires Kubernetes API access.",
                    resource_type="service_account",
                    category="OVERPRIVILEGE",
                ))

            # IAM-K8S-005: serviceAccountName missing or default
            if re.search(r"serviceAccountName\s*:\s*(default|\"default\"|'default')", line, re.IGNORECASE):
                findings.append(IAMFinding(
                    rule_id="IAM-K8S-005",
                    file=path,
                    line=i,
                    severity="LOW",
                    description="Default service account used — workloads should use dedicated service accounts",
                    recommendation="Create a dedicated service account with minimal permissions.",
                    resource_type="service_account",
                    principal="default",
                    category="OVERPRIVILEGE",
                ))

        return findings

    # ------------------------------------------------------------------
    # Terraform IAM
    # ------------------------------------------------------------------

    def _check_terraform_iam(self, path: str, content: str) -> List[IAMFinding]:
        findings: List[IAMFinding] = []
        raw_lines = content.splitlines()

        # Parse resource blocks
        in_resource = False
        resource_type = ""
        resource_lines: List[int] = []
        brace_depth = 0

        i = 0
        while i < len(raw_lines):
            line = raw_lines[i]
            stripped = line.strip()

            # Detect resource declaration
            m = re.match(r'resource\s+"([^"]+)"\s+"[^"]+"\s*\{', line)
            if m:
                in_resource = True
                resource_type = m.group(1)
                resource_lines = [i + 1]
                brace_depth = 1
                i += 1
                continue

            if in_resource:
                brace_depth += stripped.count("{") - stripped.count("}")
                resource_lines.append(i + 1)

                if brace_depth <= 0:
                    # Analyse collected resource block
                    block_content = "\n".join(raw_lines[resource_lines[0] - 1:i + 1])
                    block_start = resource_lines[0]

                    # IAM-TF-001: aws_iam_role_policy with actions = ["*"] or actions = "*"
                    if resource_type in ("aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy"):
                        if re.search(r'actions\s*=\s*\[?\s*"?\*"?\s*\]?', block_content):
                            findings.append(IAMFinding(
                                rule_id="IAM-TF-001",
                                file=path,
                                line=block_start,
                                severity="CRITICAL",
                                description=f"Terraform {resource_type} with wildcard actions grants unrestricted permissions",
                                recommendation="Replace wildcard actions with specific actions required for the role.",
                                resource_type="policy",
                                permission="*",
                                category="WILDCARD",
                            ))

                    # IAM-TF-002: google_project_iam_member with roles/owner
                    if resource_type in ("google_project_iam_member", "google_project_iam_binding"):
                        if re.search(r'role\s*=\s*"roles/owner"', block_content):
                            findings.append(IAMFinding(
                                rule_id="IAM-TF-002",
                                file=path,
                                line=block_start,
                                severity="CRITICAL",
                                description="Terraform GCP IAM member assigned roles/owner — full project ownership granted",
                                recommendation="Replace roles/owner with least-privilege roles.",
                                resource_type="role",
                                permission="roles/owner",
                                category="OVERPRIVILEGE",
                            ))

                    # IAM-TF-003: azurerm_role_assignment with Owner
                    if resource_type == "azurerm_role_assignment":
                        if re.search(r'role_definition_name\s*=\s*"Owner"', block_content):
                            findings.append(IAMFinding(
                                rule_id="IAM-TF-003",
                                file=path,
                                line=block_start,
                                severity="CRITICAL",
                                description="Terraform Azure role assignment with Owner role grants full subscription control",
                                recommendation="Replace Owner with the most specific role needed.",
                                resource_type="role",
                                permission="Owner",
                                category="OVERPRIVILEGE",
                            ))

                    in_resource = False
                    resource_type = ""
                    resource_lines = []
                    brace_depth = 0

            i += 1

        return findings

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def _is_aws_policy(self, path: str, content: str) -> bool:
        """Heuristic: contains AWS IAM policy structure."""
        indicators = ['"Statement"', '"Action"', '"Effect"', '"Resource"', "Effect:", "Action:", "Resource:"]
        has_indicators = sum(1 for ind in indicators if ind in content) >= 2
        is_aws_file = any(
            kw in path.lower() for kw in ("iam", "policy", "aws", "permission")
        )
        return has_indicators and (is_aws_file or '"Statement"' in content)

    def _is_gcp_iam(self, path: str, content: str) -> bool:
        gcp_markers = ["roles/", "bindings:", "members:", "allUsers", "allAuthenticatedUsers"]
        return any(m in content for m in gcp_markers) and "kind: ClusterRole" not in content

    def _is_k8s_rbac(self, path: str, content: str) -> bool:
        k8s_kinds = ("ClusterRole", "ClusterRoleBinding", "RoleBinding", "Role")
        k8s_markers = ["apiVersion:", "kind:", "metadata:", "rules:", "subjects:"]
        has_kind = any(f"kind: {k}" in content for k in k8s_kinds)
        pod_kinds = ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob")
        has_pod_kind = any(f"kind: {k}" in content for k in pod_kinds)
        has_markers = sum(1 for m in k8s_markers if m in content) >= 2
        return (has_kind or has_pod_kind) and has_markers

    def _is_azure_rbac(self, path: str, content: str) -> bool:
        azure_markers = [
            "roleDefinitionId", "roleAssignment", "Microsoft.Authorization",
            "azurerm_role_assignment",
        ]
        return any(m in content for m in azure_markers)

    def _is_terraform(self, path: str, content: str) -> bool:
        return path.endswith(".tf") or bool(re.search(r'resource\s+"[^"]+"\s+"[^"]+"\s*\{', content))

    def scan_file(self, path: str) -> List[IAMFinding]:
        """Detect file type and run appropriate IAM checks."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            return []

        if not content.strip():
            return []

        findings: List[IAMFinding] = []
        ext = os.path.splitext(path)[1].lower()

        if self._is_terraform(path, content):
            findings.extend(self._check_terraform_iam(path, content))
        elif self._is_k8s_rbac(path, content):
            findings.extend(self._check_k8s_rbac(path, content))
        elif self._is_aws_policy(path, content):
            findings.extend(self._check_aws_iam_policy(path, content))
        elif self._is_azure_rbac(path, content):
            findings.extend(self._check_azure_rbac(path, content))
        elif self._is_gcp_iam(path, content):
            findings.extend(self._check_gcp_iam(path, content))
        else:
            # Run all checks for ambiguous files
            if ext in (".json", ".yaml", ".yml"):
                if '"Statement"' in content or "Statement:" in content:
                    findings.extend(self._check_aws_iam_policy(path, content))
                if "roles/" in content:
                    findings.extend(self._check_gcp_iam(path, content))

        return findings

    def scan_directory(self, directory: str) -> List[IAMFinding]:
        """Walk directory tree and scan all relevant IAM config files."""
        all_findings: List[IAMFinding] = []
        skip_dirs = {"node_modules", ".git", ".tox", "__pycache__", "venv", ".venv"}
        valid_exts = {".json", ".yaml", ".yml", ".tf"}

        for root, dirs, files in os.walk(directory):
            # Prune skipped directories in-place
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if os.path.splitext(fname)[1].lower() in valid_exts:
                    fpath = os.path.join(root, fname)
                    all_findings.extend(self.scan_file(fpath))

        return all_findings


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def scan_iam(directory: str) -> List[IAMFinding]:
    """Scan a directory for IAM misconfigurations."""
    return IAMScanner().scan_directory(directory)
