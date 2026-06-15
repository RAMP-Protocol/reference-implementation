"""ADR-008 D5 cleanup fixtures.

Each module registers a function that runs in the
``shared-clean-fixtures`` cleanup chain — between tests declaring the
``stack_isolation("shared-clean-fixtures")`` marker. Tests do NOT
import these fixtures directly; the framework's per-test hook reads
the declared mode and dispatches the appropriate cleanups (D5).

Adding a new cleanup: write ``cleanup_<thing>(stack_urls)`` here and
register it from ``conftest.py``'s
``shared_clean_fixtures_chain`` so the per-test hook picks it up.
"""
