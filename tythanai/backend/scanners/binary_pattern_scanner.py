"""TythanAI — Binary Pattern Scanner
Detects dangerous patterns that survive decades of automated testing:
format string bugs, integer overflow/underflow, use-after-free, off-by-one,
buffer overflows, null pointer dereferences, race conditions, double-free.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.binary_pattern_scanner")

# ─────────────────────────────────────────────────────────────────────────────
# Rule definitions  (40+ rules)
# ─────────────────────────────────────────────────────────────────────────────

_BINARY_PATTERNS: List[Dict] = [
    # ── FORMAT_STRING ──────────────────────────────────────────────────────────
    {
        "id": "BPS-FS-001",
        "name": "printf with non-literal format string",
        "pattern": r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "printf() called with a non-literal first argument — classic format string vulnerability.",
        "recommendation": "Always pass a literal format string: printf(\"%s\", user_input).",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },
    {
        "id": "BPS-FS-002",
        "name": "sprintf without format specifier",
        "pattern": r"\bsprintf\s*\(\s*\w+\s*,\s*[a-zA-Z_][a-zA-Z0-9_.>-]*\s*\)",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "sprintf() called without a literal format string — allows format string injection.",
        "recommendation": "Use snprintf with a literal format: snprintf(buf, sizeof(buf), \"%s\", src).",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },
    {
        "id": "BPS-FS-003",
        "name": "fprintf with non-literal format string",
        "pattern": r"\bfprintf\s*\(\s*\w+\s*,\s*[a-zA-Z_][a-zA-Z0-9_.>-]*\s*\)",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "fprintf() called with a variable as format string.",
        "recommendation": "Use fprintf(stream, \"%s\", buf) with a literal format specifier.",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },
    {
        "id": "BPS-FS-004",
        "name": "syslog with non-literal format string",
        "pattern": r"\bsyslog\s*\(\s*\w+\s*,\s*[a-zA-Z_][a-zA-Z0-9_.>-]*\s*\)",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "syslog() called with a variable as format string — exploitable via attacker-controlled log messages.",
        "recommendation": "Use syslog(LOG_ERR, \"%s\", buf) with a literal format specifier.",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },
    {
        "id": "BPS-FS-005",
        "name": "vsprintf misuse — no format literal",
        "pattern": r"\bvsprintf\s*\(",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "vsprintf() is inherently unsafe — no bounds checking and prone to format string bugs.",
        "recommendation": "Replace vsprintf with vsnprintf and ensure the format string is a trusted literal.",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },
    {
        "id": "BPS-FS-006",
        "name": "vprintf with variable format",
        "pattern": r"\bvprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_.>-]*\s*,",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "vprintf() called with a non-literal format argument.",
        "recommendation": "Ensure the format argument is a compile-time string literal.",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },
    {
        "id": "BPS-FS-007",
        "name": "wprintf with variable format",
        "pattern": r"\bwprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_.>-]*\s*[,)]",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "wprintf() called with a non-literal wide format string.",
        "recommendation": "Use a literal wide format string: wprintf(L\"%s\", buf).",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },

    # ── INTEGER_OVERFLOW ───────────────────────────────────────────────────────
    {
        "id": "BPS-IO-001",
        "name": "malloc with unchecked multiplication",
        "pattern": r"\bmalloc\s*\(\s*\w+\s*\*\s*sizeof\s*\(",
        "severity": "HIGH",
        "cwe_id": "CWE-190",
        "description": "malloc(n * sizeof(T)) without overflow check — if n is attacker-controlled, the product can wrap and allocate too-small buffer.",
        "recommendation": "Use calloc(n, sizeof(T)) or check: if (n > SIZE_MAX / sizeof(T)) handle_overflow();",
        "language": ["c", "cpp"],
        "category": "INTEGER_OVERFLOW",
    },
    {
        "id": "BPS-IO-002",
        "name": "atoi on untrusted input",
        "pattern": r"\batoi\s*\(",
        "severity": "MEDIUM",
        "cwe_id": "CWE-190",
        "description": "atoi() does not detect overflow and returns int — use strtol/strtoul with range checks.",
        "recommendation": "Replace atoi with strtol and check errno and the return value against INT_MAX/INT_MIN.",
        "language": ["c", "cpp"],
        "category": "INTEGER_OVERFLOW",
    },
    {
        "id": "BPS-IO-003",
        "name": "strtol cast to int without range check",
        "pattern": r"\(int\)\s*strtol\s*\(",
        "severity": "MEDIUM",
        "cwe_id": "CWE-190",
        "description": "strtol() return value cast to int without checking for overflow — result may be truncated.",
        "recommendation": "Check that the returned long fits within INT_MIN..INT_MAX before casting.",
        "language": ["c", "cpp"],
        "category": "INTEGER_OVERFLOW",
    },
    {
        "id": "BPS-IO-004",
        "name": "signed/unsigned comparison",
        "pattern": r"(?:if|while|for)\s*\(.*\b(?:int|long)\b[^=]*[<>]=?\s*(?:strlen|sizeof|unsigned)",
        "severity": "MEDIUM",
        "cwe_id": "CWE-195",
        "description": "Comparison between signed and unsigned integer — negative signed value compares greater than large unsigned value.",
        "recommendation": "Cast both sides to the same type (size_t for lengths) before comparing.",
        "language": ["c", "cpp"],
        "category": "INTEGER_OVERFLOW",
    },
    {
        "id": "BPS-IO-005",
        "name": "unsigned wrap-around in arithmetic",
        "pattern": r"\bunsigned\s+(?:int|long|short)\s+\w+\s*=[^;]*-\s*1\b",
        "severity": "MEDIUM",
        "cwe_id": "CWE-191",
        "description": "Unsigned integer arithmetic that could underflow/wrap to UINT_MAX.",
        "recommendation": "Check that the operand is > 0 before subtracting 1 from an unsigned variable.",
        "language": ["c", "cpp"],
        "category": "INTEGER_OVERFLOW",
    },
    {
        "id": "BPS-IO-006",
        "name": "realloc size multiplication without check",
        "pattern": r"\brealloc\s*\(\s*\w+\s*,\s*\w+\s*\*",
        "severity": "HIGH",
        "cwe_id": "CWE-190",
        "description": "realloc() called with a multiplied size — overflow in the size argument can cause heap underallocation.",
        "recommendation": "Check for overflow before the multiplication and use a safe size helper.",
        "language": ["c", "cpp"],
        "category": "INTEGER_OVERFLOW",
    },

    # ── USE_AFTER_FREE ─────────────────────────────────────────────────────────
    {
        "id": "BPS-UAF-001",
        "name": "use of pointer after free",
        "pattern": r"free\s*\(\s*(\w+)\s*\).*\1\s*(?:->|\[|\+)",
        "severity": "HIGH",
        "cwe_id": "CWE-416",
        "description": "Pointer is accessed after being freed — use-after-free leads to memory corruption or remote code execution.",
        "recommendation": "Set pointer to NULL immediately after free(): free(p); p = NULL;",
        "language": ["c", "cpp"],
        "category": "USE_AFTER_FREE",
    },
    {
        "id": "BPS-UAF-002",
        "name": "freed pointer passed to function",
        "pattern": r"free\s*\(\s*(\w+)\s*\)\s*;\s*\w+\s*\(\s*\1",
        "severity": "HIGH",
        "cwe_id": "CWE-416",
        "description": "A freed pointer is passed as an argument to another function — dangling pointer dereference.",
        "recommendation": "Null-check and reassign the pointer before any subsequent use after free().",
        "language": ["c", "cpp"],
        "category": "USE_AFTER_FREE",
    },
    {
        "id": "BPS-UAF-003",
        "name": "dangling pointer — return of local address",
        "pattern": r"return\s+&[a-zA-Z_]\w*\s*;",
        "severity": "HIGH",
        "cwe_id": "CWE-562",
        "description": "Function returns address of a local (stack) variable — the address is invalid after the function returns.",
        "recommendation": "Allocate the returned value on the heap or pass an output parameter by pointer.",
        "language": ["c", "cpp"],
        "category": "USE_AFTER_FREE",
    },
    {
        "id": "BPS-UAF-004",
        "name": "use-after-free in Rust — raw pointer after drop",
        "pattern": r"drop\s*\(.*\)\s*;[\s\S]{0,120}unsafe\s*\{[^}]*\*",
        "severity": "HIGH",
        "cwe_id": "CWE-416",
        "description": "Unsafe raw pointer dereference after explicit drop() — potential use-after-free in Rust unsafe block.",
        "recommendation": "Never dereference a raw pointer that points to dropped memory; restructure ownership.",
        "language": ["rust"],
        "category": "USE_AFTER_FREE",
    },

    # ── BUFFER_OVERFLOW ────────────────────────────────────────────────────────
    {
        "id": "BPS-BO-001",
        "name": "strcpy without bounds check",
        "pattern": r"\bstrcpy\s*\(",
        "severity": "HIGH",
        "cwe_id": "CWE-120",
        "description": "strcpy() performs no bounds checking — if source is longer than destination buffer, stack/heap smashing occurs.",
        "recommendation": "Replace with strlcpy(dst, src, sizeof(dst)) or strncpy with explicit NUL termination.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-BO-002",
        "name": "strcat without bounds check",
        "pattern": r"\bstrcat\s*\(",
        "severity": "HIGH",
        "cwe_id": "CWE-120",
        "description": "strcat() appends without checking available space — can overflow the destination buffer.",
        "recommendation": "Use strlcat(dst, src, sizeof(dst)) or maintain explicit size tracking.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-BO-003",
        "name": "gets — unconditionally unsafe",
        "pattern": r"\bgets\s*\(",
        "severity": "CRITICAL",
        "cwe_id": "CWE-120",
        "description": "gets() reads an unbounded string — removed from C11; always causes buffer overflow with long input.",
        "recommendation": "Replace with fgets(buf, sizeof(buf), stdin) and strip the trailing newline.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-BO-004",
        "name": "sprintf destination overflow",
        "pattern": r"\bsprintf\s*\(",
        "severity": "HIGH",
        "cwe_id": "CWE-120",
        "description": "sprintf() writes without a length limit — use snprintf to prevent buffer overflow.",
        "recommendation": "Replace sprintf(buf, ...) with snprintf(buf, sizeof(buf), ...).",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-BO-005",
        "name": "memcpy with user-controlled size",
        "pattern": r"\bmemcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*(?:len|size|n|count|length|user_len|req_len|recv_len)\b",
        "severity": "HIGH",
        "cwe_id": "CWE-120",
        "description": "memcpy() called with a potentially attacker-controlled size argument — can overflow destination.",
        "recommendation": "Validate size <= sizeof(dst) and size > 0 before calling memcpy.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-BO-006",
        "name": "variable-length stack allocation",
        "pattern": r"\bchar\s+\w+\s*\[\s*[a-zA-Z_]\w*\s*\]",
        "severity": "MEDIUM",
        "cwe_id": "CWE-121",
        "description": "Stack allocation with a variable size — a large or attacker-controlled n can overflow the stack.",
        "recommendation": "Use heap allocation (malloc) with size validation when the size is not a compile-time constant.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-BO-007",
        "name": "strncat with sizeof destination",
        "pattern": r"\bstrncat\s*\(\s*\w+\s*,\s*\w+\s*,\s*sizeof\s*\(",
        "severity": "MEDIUM",
        "cwe_id": "CWE-120",
        "description": "strncat(dst, src, sizeof(dst)) counts from the START of dst, not remaining space — off-by-design overflow.",
        "recommendation": "Use strlcat or compute remaining space: sizeof(dst) - strlen(dst) - 1.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },

    # ── OFF_BY_ONE ─────────────────────────────────────────────────────────────
    {
        "id": "BPS-OBO-001",
        "name": "loop index <= strlen",
        "pattern": r"(?:for|while)\s*\([^;]*;\s*\w+\s*<=\s*strlen\s*\(",
        "severity": "MEDIUM",
        "cwe_id": "CWE-193",
        "description": "Loop iterates with index <= strlen(s) — includes the NUL terminator, causing an off-by-one overread.",
        "recommendation": "Use strict less-than: i < strlen(s). Pre-compute the length outside the loop.",
        "language": ["c", "cpp"],
        "category": "OFF_BY_ONE",
    },
    {
        "id": "BPS-OBO-002",
        "name": "loop index <= sizeof",
        "pattern": r"(?:for|while)\s*\([^;]*;\s*\w+\s*<=\s*sizeof\s*\(",
        "severity": "MEDIUM",
        "cwe_id": "CWE-193",
        "description": "Loop iterates with index <= sizeof(buf) — accesses one byte past the buffer end.",
        "recommendation": "Use strict less-than: i < sizeof(buf).",
        "language": ["c", "cpp"],
        "category": "OFF_BY_ONE",
    },
    {
        "id": "BPS-OBO-003",
        "name": "loop with <= MAX constant",
        "pattern": r"(?:for|while)\s*\([^;]*;\s*\w+\s*<=\s*(?:MAX|MAX_\w+|BUFSIZE|BUF_SIZE|MAXLEN)\b",
        "severity": "MEDIUM",
        "cwe_id": "CWE-193",
        "description": "Loop uses <= MAX — when indices are 0-based, the last iteration accesses index MAX which is out-of-bounds.",
        "recommendation": "Use i < MAX for 0-based indexing.",
        "language": ["c", "cpp"],
        "category": "OFF_BY_ONE",
    },
    {
        "id": "BPS-OBO-004",
        "name": "memcpy with strlen+1 past buffer",
        "pattern": r"\bmemcpy\s*\([^,]+,[^,]+,\s*strlen\s*\([^)]+\)\s*\+\s*1\s*\)",
        "severity": "MEDIUM",
        "cwe_id": "CWE-193",
        "description": "memcpy using strlen(src)+1 copies the NUL terminator but can overflow if dst is exactly strlen bytes.",
        "recommendation": "Ensure dst has at least strlen(src)+1 bytes allocated before this call.",
        "language": ["c", "cpp"],
        "category": "OFF_BY_ONE",
    },
    {
        "id": "BPS-OBO-005",
        "name": "array index off by one",
        "pattern": r"\w+\s*\[\s*(?:sizeof|strlen)\s*\([^)]+\)\s*\]",
        "severity": "HIGH",
        "cwe_id": "CWE-193",
        "description": "Array indexed by sizeof()/strlen() — valid indices are 0..N-1; index N is out of bounds.",
        "recommendation": "Subtract 1: buf[sizeof(buf)-1] = '\\0';",
        "language": ["c", "cpp"],
        "category": "OFF_BY_ONE",
    },

    # ── NULL_DEREF ─────────────────────────────────────────────────────────────
    {
        "id": "BPS-ND-001",
        "name": "malloc return not checked",
        "pattern": r"\bmalloc\s*\([^;]+\)\s*;",
        "severity": "MEDIUM",
        "cwe_id": "CWE-476",
        "description": "malloc() return value used without NULL check — returns NULL on allocation failure, causing null dereference.",
        "recommendation": "Always check: ptr = malloc(n); if (!ptr) { handle_oom(); }",
        "language": ["c", "cpp"],
        "category": "NULL_DEREF",
    },
    {
        "id": "BPS-ND-002",
        "name": "fopen return not checked",
        "pattern": r"\bfopen\s*\([^;]+\)\s*;",
        "severity": "MEDIUM",
        "cwe_id": "CWE-476",
        "description": "fopen() return value not checked — if file does not exist or permission denied, returns NULL.",
        "recommendation": "Always check: fp = fopen(path, mode); if (!fp) { perror(path); return -1; }",
        "language": ["c", "cpp"],
        "category": "NULL_DEREF",
    },
    {
        "id": "BPS-ND-003",
        "name": "pointer arithmetic without null check",
        "pattern": r"(?:->|(?<!\w)\*\s*)\w+[^=;]*(?:\[|\+\+|--|\+\s*\d)",
        "severity": "MEDIUM",
        "cwe_id": "CWE-476",
        "description": "Pointer arithmetic or member access without prior null check — may dereference NULL.",
        "recommendation": "Add an explicit null check before dereferencing any pointer that could be NULL.",
        "language": ["c", "cpp"],
        "category": "NULL_DEREF",
    },
    {
        "id": "BPS-ND-004",
        "name": "calloc return not checked",
        "pattern": r"\bcalloc\s*\([^;]+\)\s*;",
        "severity": "MEDIUM",
        "cwe_id": "CWE-476",
        "description": "calloc() return value used without NULL check.",
        "recommendation": "Check the return value of calloc() before use.",
        "language": ["c", "cpp"],
        "category": "NULL_DEREF",
    },
    {
        "id": "BPS-ND-005",
        "name": "realloc overwrites original pointer",
        "pattern": r"\b(\w+)\s*=\s*realloc\s*\(\s*\1\s*,",
        "severity": "HIGH",
        "cwe_id": "CWE-476",
        "description": "ptr = realloc(ptr, ...) — if realloc fails it returns NULL but the original pointer is lost (memory leak + null deref).",
        "recommendation": "Use a temporary: tmp = realloc(ptr, n); if (tmp) ptr = tmp; else handle_error();",
        "language": ["c", "cpp"],
        "category": "NULL_DEREF",
    },

    # ── DOUBLE_FREE ────────────────────────────────────────────────────────────
    {
        "id": "BPS-DF-001",
        "name": "free called twice on same variable",
        "pattern": r"free\s*\(\s*(\w+)\s*\)\s*;[^}]*free\s*\(\s*\1\s*\)",
        "severity": "HIGH",
        "cwe_id": "CWE-415",
        "description": "free() called twice on the same pointer — double-free corrupts the heap allocator and enables exploitation.",
        "recommendation": "Set pointer to NULL after the first free(); if (!ptr) return; free(ptr); ptr = NULL;",
        "language": ["c", "cpp"],
        "category": "DOUBLE_FREE",
    },
    {
        "id": "BPS-DF-002",
        "name": "free in both if and else branches",
        "pattern": r"if\s*\([^)]+\)\s*\{[^}]*\bfree\s*\(\s*(\w+)\s*\)[^}]*\}\s*else\s*\{[^}]*\bfree\s*\(\s*\1\s*\)",
        "severity": "HIGH",
        "cwe_id": "CWE-415",
        "description": "Pointer is freed in both if and else branches — if the pointer is the same object this is a double-free.",
        "recommendation": "Refactor to free the pointer once after the conditional, or ensure separate pointers.",
        "language": ["c", "cpp"],
        "category": "DOUBLE_FREE",
    },
    {
        "id": "BPS-DF-003",
        "name": "free in exception/error path after normal free",
        "pattern": r"free\s*\(\s*(\w+)\s*\)\s*;.*(?:goto\s+\w+|return\s+-?\d+)\s*;[\s\S]{0,300}\bfree\s*\(\s*\1\s*\)",
        "severity": "HIGH",
        "cwe_id": "CWE-415",
        "description": "Pointer freed before goto/return, then freed again in error handler — double-free on error path.",
        "recommendation": "Use a single cleanup label with null-guard: if (ptr) { free(ptr); ptr = NULL; }",
        "language": ["c", "cpp"],
        "category": "DOUBLE_FREE",
    },

    # ── RACE_CONDITION ─────────────────────────────────────────────────────────
    {
        "id": "BPS-RC-001",
        "name": "global variable access without mutex",
        "pattern": r"\bg_\w+\s*(?:[+\-*/&|^]=|=(?!=)|\+\+|--)",
        "severity": "MEDIUM",
        "cwe_id": "CWE-362",
        "description": "Access to a global variable (g_ prefix convention) without visible mutex protection — potential race condition.",
        "recommendation": "Protect shared state with a mutex: pthread_mutex_lock(&mtx); ... pthread_mutex_unlock(&mtx);",
        "language": ["c", "cpp"],
        "category": "RACE_CONDITION",
    },
    {
        "id": "BPS-RC-002",
        "name": "time() used for security decision",
        "pattern": r"\btime\s*\(\s*(?:NULL|0)\s*\)",
        "severity": "MEDIUM",
        "cwe_id": "CWE-362",
        "description": "time() used — its granularity (1 second) makes it predictable for security-relevant seeds or tokens.",
        "recommendation": "Use a CSPRNG (e.g., getrandom, /dev/urandom) for security-relevant randomness, not time().",
        "language": ["c", "cpp"],
        "category": "RACE_CONDITION",
    },
    {
        "id": "BPS-RC-003",
        "name": "TOCTOU — access() followed by open()",
        "pattern": r"\baccess\s*\([^;]+\)\s*;[^}]{0,200}\bopen\s*\(",
        "severity": "HIGH",
        "cwe_id": "CWE-367",
        "description": "access() then open() TOCTOU race — file state can change between the check and the use.",
        "recommendation": "Open the file directly and handle the permission error; avoid access() for permission checks.",
        "language": ["c", "cpp"],
        "category": "RACE_CONDITION",
    },
    {
        "id": "BPS-RC-004",
        "name": "non-atomic file existence check",
        "pattern": r"\bstat\s*\([^;]+\)\s*;\s*(?:if|//)[^}]{0,200}\bopen\s*\(",
        "severity": "MEDIUM",
        "cwe_id": "CWE-367",
        "description": "stat() followed by open() — another TOCTOU race between existence check and file open.",
        "recommendation": "Use open() directly with O_CREAT|O_EXCL for atomic create-if-not-exists semantics.",
        "language": ["c", "cpp"],
        "category": "RACE_CONDITION",
    },
    {
        "id": "BPS-RC-005",
        "name": "Rust shared reference across threads without Send/Sync",
        "pattern": r"Arc\s*::\s*new\s*\(.*Mutex\s*::\s*new",
        "severity": "LOW",
        "cwe_id": "CWE-362",
        "description": "Arc<Mutex<T>> detected — correct pattern for thread-sharing in Rust; verify lock is always held.",
        "recommendation": "Ensure every access to the inner value holds the lock and avoid lock poisoning.",
        "language": ["rust"],
        "category": "RACE_CONDITION",
    },

    # Extra rules to exceed 40 total ──────────────────────────────────────────
    {
        "id": "BPS-BO-008",
        "name": "scanf without width limit",
        "pattern": r'\bscanf\s*\(\s*"[^"]*%s',
        "severity": "HIGH",
        "cwe_id": "CWE-120",
        "description": "scanf(\"%s\", buf) without a width limit reads unbounded input — classic stack buffer overflow.",
        "recommendation": "Use scanf(\"%255s\", buf) or fgets for safer input reading.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-BO-009",
        "name": "memmove with user-controlled size",
        "pattern": r"\bmemmove\s*\(\s*\w+\s*,\s*\w+\s*,\s*(?:len|size|n|count|length|user_len)\b",
        "severity": "HIGH",
        "cwe_id": "CWE-120",
        "description": "memmove() called with a user-controlled size argument.",
        "recommendation": "Validate that size <= sizeof(dst) before calling memmove.",
        "language": ["c", "cpp"],
        "category": "BUFFER_OVERFLOW",
    },
    {
        "id": "BPS-IO-007",
        "name": "calloc with untrusted n",
        "pattern": r"\bcalloc\s*\(\s*(?:user_|attacker_|req_|recv_)?\w+\s*,",
        "severity": "MEDIUM",
        "cwe_id": "CWE-190",
        "description": "calloc(n, size) — if n is attacker-controlled a zero-value or overflow may produce a tiny allocation.",
        "recommendation": "Validate n is within a safe range before calling calloc.",
        "language": ["c", "cpp"],
        "category": "INTEGER_OVERFLOW",
    },
    {
        "id": "BPS-FS-008",
        "name": "snprintf format not a literal",
        "pattern": r"\bsnprintf\s*\(\s*\w+\s*,\s*\w+\s*,\s*[a-zA-Z_][a-zA-Z0-9_.>-]*\s*[,)]",
        "severity": "HIGH",
        "cwe_id": "CWE-134",
        "description": "snprintf() called with a variable format string — still exploitable for format string attacks.",
        "recommendation": "The third argument to snprintf must be a string literal.",
        "language": ["c", "cpp"],
        "category": "FORMAT_STRING",
    },
    {
        "id": "BPS-ND-006",
        "name": "strdup return not null-checked",
        "pattern": r"\bstrdup\s*\([^;]+\)\s*;",
        "severity": "MEDIUM",
        "cwe_id": "CWE-476",
        "description": "strdup() return value not checked for NULL — allocation can fail.",
        "recommendation": "Always check: p = strdup(s); if (!p) { /* handle OOM */ }",
        "language": ["c", "cpp"],
        "category": "NULL_DEREF",
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Language detection
# ─────────────────────────────────────────────────────────────────────────────

_EXT_TO_LANG: Dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".rs": "rust",
}

_SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "build", "dist"}


def _detect_language(path: str) -> Optional[str]:
    ext = Path(path).suffix.lower()
    return _EXT_TO_LANG.get(ext)


def _compile_patterns() -> List[tuple]:
    """Pre-compile all regexes once."""
    compiled = []
    for rule in _BINARY_PATTERNS:
        try:
            rx = re.compile(rule["pattern"], re.MULTILINE | re.DOTALL)
        except re.error as exc:  # pragma: no cover
            logger.warning("Invalid pattern in rule %s: %s", rule["id"], exc)
            continue
        compiled.append((rx, rule))
    return compiled


_COMPILED_PATTERNS = _compile_patterns()


def _context_lines(lines: List[str], lineno: int, radius: int = 2) -> List[str]:
    start = max(0, lineno - radius - 1)
    end = min(len(lines), lineno + radius)
    return lines[start:end]


# ─────────────────────────────────────────────────────────────────────────────
# Scanner class
# ─────────────────────────────────────────────────────────────────────────────

class BinaryPatternScanner:
    """
    Deep scanner for dangerous low-level patterns in C/C++/Rust source files.

    Methods
    -------
    scan_file(path)         → List[Finding]
    scan_directory(path)    → List[Finding]
    get_rules_by_category(category) → List[Dict]
    """

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a single source file and return all findings."""
        lang = _detect_language(path)
        if lang is None:
            logger.debug("Skipping unsupported file: %s", path)
            return []

        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []

        lines = content.splitlines()
        findings: List[Finding] = []
        seen: set = set()

        for rx, rule in _COMPILED_PATTERNS:
            # Filter by language
            if lang not in rule["language"]:
                continue

            for match in rx.finditer(content):
                # Compute line number from match start offset
                lineno = content[: match.start()].count("\n") + 1
                key = (path, lineno, rule["id"])
                if key in seen:
                    continue
                seen.add(key)

                ctx = _context_lines(lines, lineno)
                findings.append(
                    Finding(
                        rule_id=f"{rule['category']}-{rule['id'].split('-')[-1]}",
                        file=path,
                        line=lineno,
                        severity=rule["severity"],
                        cwe_id=rule["cwe_id"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        confidence=0.85,
                        sources=[path],
                        context_lines=ctx,
                    )
                )

        return findings

    def scan_directory(
        self,
        path: str,
        extensions: tuple = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".rs"),
    ) -> List[Finding]:
        """Recursively scan all matching files in a directory."""
        findings: List[Finding] = []
        ext_set = set(extensions)

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                if Path(fname).suffix.lower() in ext_set:
                    findings.extend(self.scan_file(os.path.join(root, fname)))

        return findings

    def get_rules_by_category(self, category: str) -> List[Dict]:
        """Return all rules belonging to the given category (case-insensitive)."""
        cat_upper = category.upper()
        return [r for r in _BINARY_PATTERNS if r["category"] == cat_upper]


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience
# ─────────────────────────────────────────────────────────────────────────────

def scan_binary_patterns(path: str) -> List[Finding]:
    """Scan *path* (file or directory) for binary-level dangerous patterns."""
    scanner = BinaryPatternScanner()
    if os.path.isdir(path):
        return scanner.scan_directory(path)
    return scanner.scan_file(path)
