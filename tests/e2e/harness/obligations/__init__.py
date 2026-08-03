"""Obligation-driven E2E tests.

Each module under this package traces to a single happy-path or failure-mode
bullet of one behavioural obligation. The scenario text (verbatim) is the test
docstring; the xfail reason mirrors that bullet when production does not yet
exhibit the asserted behavior.
"""
