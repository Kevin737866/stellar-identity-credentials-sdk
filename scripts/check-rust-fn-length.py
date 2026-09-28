#!/usr/bin/env python3
"""Check Rust source files for functions exceeding a maximum line count.

Usage: python3 scripts/check-rust-fn-length.py [--max N] [src_dir...]
"""
import sys
import re
import os
from pathlib import Path


def count_function_lines(filepath: str, max_lines: int) -> list[str]:
    """Find Rust functions exceeding max_lines. Returns list of violations."""
    violations = []
    with open(filepath) as f:
        lines = f.readlines()

    # Simple state machine: track brace depth after a 'fn' declaration
    # Matches: fn, pub fn, pub(crate) fn, pub(super) fn, async fn, unsafe fn, extern "C" fn
    # and combinations like `pub async fn`, `async unsafe fn`, etc.
    FN_RE = re.compile(
        r'(?:pub(?:\s*\(\s*\w+\s*\))?\s+)?'
        r'(?:async\s+)?'
        r'(?:unsafe\s+)?'
        r'(?:extern\s+(?:"[^"]*"\s+)?)?'
        r'fn\s+(\w+)'
    )

    in_fn = False
    fn_start_line = 0
    fn_name = ""
    brace_depth = 0
    fn_line_count = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not in_fn:
            m = FN_RE.match(stripped)
            if m:
                in_fn = True
                fn_name = m.group(1)
                fn_start_line = i
                brace_depth = 0
                fn_line_count = 0
                # Check if opening brace is on this line
                if '{' in stripped:
                    brace_depth += stripped.count('{') - stripped.count('}')
                continue
        else:
            fn_line_count += 1
            # Track braces
            brace_depth += stripped.count('{') - stripped.count('}')
            if brace_depth <= 0:
                # Function ended
                if fn_line_count > max_lines:
                    violations.append(
                        f"{filepath}:{fn_start_line}: function '{fn_name}' "
                        f"is {fn_line_count} lines (max {max_lines})"
                    )
                in_fn = False

    return violations


def main():
    max_lines = 100
    args = sys.argv[1:]

    # Parse optional --max flag
    if args and args[0] == '--max':
        max_lines = int(args[1])
        args = args[2:]

    dirs = args if args else ['src']

    violations = []
    for d in dirs:
        for root, _, files in os.walk(d):
            for f in files:
                if f.endswith('.rs'):
                    violations.extend(
                        count_function_lines(os.path.join(root, f), max_lines)
                    )

    if violations:
        print(f"Found {len(violations)} function(s) exceeding {max_lines} lines:")
        for v in violations:
            print(f"  {v}")
        sys.exit(1)
    else:
        print(f"All Rust functions are within {max_lines} lines.")
        sys.exit(0)


if __name__ == '__main__':
    main()
