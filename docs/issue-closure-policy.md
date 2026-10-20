# Issue Closure Policy

> Adopted in response to the repository audit finding that closed issues
> were treated as delivery evidence without verification (Issue #515).
> Several closed issues described capabilities that were stubbed, undeclared
> or unenforced in any executable path, so tracker state could not be used
> to judge readiness.

## Rule

An issue may only be closed when **one** of the following holds:

1. **Implemented and verified** — a merged change implements the
   behaviour **and** a test exists that fails without the change. The
   closing comment (or PR body) links to both the commit/PR and the test.
2. **Explicitly won't implement** — the maintainers recorded a
   "won't implement" decision in the issue with a short rationale.
   Label the issue `wontfix`.
3. **Duplicate** — the issue duplicates another issue; close with a
   reference to the canonical issue.

A closed issue without one of these three justifications is not evidence
of anything.

## Closure checklist (paste into the closing comment)

```
Closes #<number>

## Closure evidence
- [ ] Change: PR #<n> (merged commit <sha>)
- [ ] Test: <path/to/test> — fails without the change, passes with it
- [ ] Acceptance criteria from the issue body re-verified on <branch/env>
- [ ] No dependent issue was closed by this change without its own evidence
```

For "won't implement" closures:

```
Closes #<number> (wontfix)

## Rationale
<why this will not be implemented; who decided; date>
```

## Reviewer responsibilities

Reviewers must not approve a PR whose body says "closes #N" unless the PR
contains the test that demonstrates the behaviour. If the test is deferred,
split the issue: close only the part that ships with evidence and re-file
the remainder.

## Release verification

The release checklist includes a step that samples the issues closed in the
release window and re-runs their acceptance criteria (or confirms the linked
test still passes). An issue that cannot be re-verified is reopened before
tagging.

## Audit-identified gaps

Closed issues whose implementations were found to be non-executable by the
audit (privacy features, GDPR erasure, geographic restriction, regulatory
reporting, presentation flow, credential encryption, fuzz testing,
property-based reputation tests, audit trail, pause-guard enforcement) must
be reopened or re-filed with a reference to the audit evidence before they
can be counted as delivered again.
