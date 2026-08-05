"""Human-facing landing page at the demo publisher's site root.

A stakeholder demo starts by opening the demo hostname in a browser, so the
first page a person sees must be the catalog index, not a 404. The page is
static content baked into the origin (deploy/content/demo/index.html, routed
by deploy/publisher/nginx.conf); these tests drive it through the compose
stack's edge worker — the same surface a real browser hits — so they prove
the whole chain: edge bot gate -> pass-through -> origin nginx -> index file.

The bot side is the negative path of the same URL: the landing page must not
open a hole in the bot gate at the root.
"""

from __future__ import annotations

import re

import httpx

from .conftest import StackURLs
from .constants import AI_BOT_UA, BROWSER_UA


def test_browser_at_site_root_gets_the_catalog_index(compose_stack: StackURLs) -> None:
    """A browser at / gets 200 HTML naming the three fictional publishers."""
    resp = httpx.get(f"{compose_stack.edge}/", timeout=10.0, headers={"User-Agent": BROWSER_UA})
    assert resp.status_code == httpx.codes.OK, resp.text[:300]
    assert resp.headers.get("content-type", "").startswith("text/html"), resp.headers
    for publisher_name in ("Stoa Press", "Harmonia Records", "FoleyWorks"):
        assert publisher_name in resp.text, f"landing page does not name {publisher_name}"


def test_every_landing_page_link_resolves_through_the_edge(compose_stack: StackURLs) -> None:
    """Every link on the page is fetchable by the same browser (200).

    Guards the page against drifting from the served tree: the hrefs are read
    out of the served page itself, so a link to a file that does not exist —
    or a page edit that breaks a path — fails here, not in front of a
    stakeholder. A page with no links at all also fails: that would mean the
    extraction went wrong, not that everything resolved.
    """
    page = httpx.get(f"{compose_stack.edge}/", timeout=10.0, headers={"User-Agent": BROWSER_UA})
    assert page.status_code == httpx.codes.OK, page.text[:300]
    hrefs = re.findall(r'href="([^"]+)"', page.text)
    assert hrefs, "landing page carries no links — href extraction found nothing"
    for href in hrefs:
        assert href.startswith("/"), f"landing page link is not site-relative: {href}"
        resp = httpx.get(
            f"{compose_stack.edge}{href}", timeout=10.0, headers={"User-Agent": BROWSER_UA}
        )
        assert resp.status_code == httpx.codes.OK, f"{href}: {resp.status_code} {resp.text[:200]}"


def test_ai_bot_at_site_root_is_sent_to_negotiate(compose_stack: StackURLs) -> None:
    """An AI bot at / is refused (403) with the ai_bot negotiation reason."""
    resp = httpx.get(f"{compose_stack.edge}/", timeout=10.0, headers={"User-Agent": AI_BOT_UA})
    assert resp.status_code == httpx.codes.FORBIDDEN, resp.text[:300]
    body = resp.json()
    assert body.get("reason") == "ai_bot", body
