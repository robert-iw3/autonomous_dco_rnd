"""
Repo-root pytest collection guard.

data_ops/ is a conceptual draft (see data_ops/README.md) — not wired into
anything yet. Keep it out of test collection for now so it can hold
non-test .py files (DAGs, Spark jobs) without pytest trying to import them.
"""

collect_ignore_glob = ["data_ops/*"]
