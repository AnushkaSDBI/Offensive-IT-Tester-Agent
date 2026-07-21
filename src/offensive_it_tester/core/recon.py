"""
Live HTTP reconnaissance: discovers injection points from a real web application.

Crawls the target's HTML pages, parses forms and URL parameters with BeautifulSoup,
and maps each discovered input field to candidate attack classes via a documented
heuristic. This replaces MockTarget.enumerate_surfaces()'s hardcoded dict with
actual HTTP discovery, closing the single biggest architectural gap identified in
the competitor analysis.

Context isolation (aegissec pattern): all text retrieved from the target is treated
as UNTRUSTED INPUT that must never be passed raw to the LLM planner or used to
construct scope-gate decisions. Field names and values are sanitized before they
enter the agent's state.

Usage:
    from offensive_it_tester.core.recon import crawl_surfaces
    surfaces = crawl_surfaces("http://127.0.0.1:5001")
"""
import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


# Heuristic: map form field names / URL paths to candidate attack classes.
# Conservative: if unsure, include more classes (the detector, not the recon, decides).
FIELD_HEURISTICS = {
    "username": ["SQLi"],
    "password": ["SQLi"],
    "user": ["SQLi"],
    "email": ["SQLi", "XSS"],
    "login": ["SQLi"],
    "search": ["XSS", "SQLi"],
    "query": ["XSS", "SQLi"],
    "q": ["XSS", "SQLi"],
    "comment": ["XSS"],
    "bio": ["XSS"],
    "name": ["XSS", "SQLi"],
    "message": ["XSS"],
    "host": ["CmdInj"],
    "ip": ["CmdInj"],
    "cmd": ["CmdInj"],
    "ping": ["CmdInj"],
    "url": ["SSRF"],
    "fetch": ["SSRF"],
    "target": ["SSRF"],
    "redirect": ["SSRF"],
    "to_account": ["CSRF"],
    "amount": ["CSRF"],
    "transfer": ["CSRF"],
}

# Path-level heuristics (if the URL path contains these, add the class)
PATH_HEURISTICS = {
    "login": ["SQLi"],
    "search": ["XSS"],
    "ping": ["CmdInj"],
    "fetch": ["SSRF"],
    "transfer": ["CSRF"],
    "profile": ["XSS"],
}

# Maximum length for any value retrieved from the target (context isolation)
MAX_FIELD_LEN = 200


def _sanitize(text: str) -> str:
    """Context isolation: strip control characters and truncate target-retrieved text
    so it cannot inject instructions into the planner or break downstream parsing."""
    clean = re.sub(r"[\x00-\x1f\x7f]", "", str(text))
    return clean[:MAX_FIELD_LEN]


def _guess_vulns(field_name: str, path: str) -> List[str]:
    """Map a form field name + URL path to candidate attack classes."""
    vulns = set()
    fl = field_name.lower()
    for pattern, classes in FIELD_HEURISTICS.items():
        if pattern in fl:
            vulns.update(classes)
    for pattern, classes in PATH_HEURISTICS.items():
        if pattern in path.lower():
            vulns.update(classes)
    if not vulns:
        vulns = {"XSS", "SQLi"}  # default: the two most common web vulns
    return sorted(vulns)


def crawl_surfaces(
    base_url: str,
    timeout: float = 10.0,
    max_pages: int = 50,
    session: Optional[requests.Session] = None,
) -> List[dict]:
    """Crawl a web application and return discovered injection surfaces.

    Each surface is a dict with: path, method, parameter, expected_vulns, source.
    """
    sess = session or requests.Session()
    visited = set()
    to_visit = [base_url]
    surfaces = []
    parsed_base = urlparse(base_url)

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = sess.get(url, timeout=timeout)
        except requests.RequestException:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        parsed = urlparse(url)
        path = parsed.path or "/"

        # --- discover forms ---
        for form in soup.find_all("form"):
            action = _sanitize(form.get("action", path))
            method = (form.get("method", "GET")).upper()
            form_path = urlparse(urljoin(url, action)).path

            for inp in form.find_all(["input", "textarea", "select"]):
                name = _sanitize(inp.get("name", ""))
                if not name or inp.get("type") in ("submit", "hidden", "button"):
                    continue
                vulns = _guess_vulns(name, form_path)
                surfaces.append({
                    "path": form_path,
                    "method": method,
                    "parameter": name,
                    "expected_vulns": vulns,
                    "source": "form",
                })

        # --- discover URL query parameters from links ---
        for a in soup.find_all("a", href=True):
            href = urljoin(url, a["href"])
            href_parsed = urlparse(href)

            # only follow links on the same host
            if href_parsed.hostname != parsed_base.hostname:
                continue
            if href_parsed.port and href_parsed.port != parsed_base.port:
                continue

            # queue for crawling
            clean_url = f"{href_parsed.scheme}://{href_parsed.netloc}{href_parsed.path}"
            if clean_url not in visited:
                to_visit.append(clean_url)

            # extract query params as surfaces
            if href_parsed.query:
                for param in href_parsed.query.split("&"):
                    if "=" in param:
                        name = _sanitize(param.split("=")[0])
                        vulns = _guess_vulns(name, href_parsed.path)
                        surfaces.append({
                            "path": href_parsed.path,
                            "method": "GET",
                            "parameter": name,
                            "expected_vulns": vulns,
                            "source": "url_param",
                        })

    # deduplicate
    seen = set()
    unique = []
    for s in surfaces:
        key = (s["path"], s["method"], s["parameter"])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique
