"""Action categories and allowed targets (Layer 6).

Rules:
- Permission comes ONLY from Eric's allowed-target list. Keywords never grant it.
- Unknown action category, or no target  -> PAUSE (ask Glow/Eric to clarify).
- Known category but unavailable in the pilot -> DENY. Eric's approval cannot enable it.
- Known, available category but target not on Eric's list -> DENY (default deny).
- Otherwise ALLOW.

In MG-001 nothing is executed by Mini Glow. These checks gate what a person (or a later
execution layer) is allowed to record as authorized.
"""

from __future__ import annotations

# Available in the pilot, but only for targets Eric has allowed.
AVAILABLE = {
    "read_file": "read a file or folder (target = path)",
    "write_file": "create or change a file in a folder (target = path)",
    "draft_text": "write draft text kept inside Mini Glow (target = local-draft)",
}

# Known but switched off in the pilot. Eric's decision cannot activate these.
UNAVAILABLE = {
    "buy": "purchases",
    "send_message": "email, chat, DM, text, invites",
    "browser_control": "driving a web browser",
    "unattended_run": "running without a person present",
    "run_program": "starting programs or scripts",
    "network_request": "calling websites or APIs",
}

KNOWN = set(AVAILABLE) | set(UNAVAILABLE)


def normalize_target(target: str) -> str | None:
    """Lower-case, forward slashes, no trailing slash. None if the target is unacceptable."""
    if target is None:
        return None
    t = target.strip().replace("\\", "/")
    while "//" in t:
        t = t.replace("//", "/")
    t = t.rstrip("/").lower()
    if not t:
        return None
    if any(seg == ".." for seg in t.split("/")):
        return None
    return t


def covers(allowed: str, target: str) -> bool:
    return target == allowed or target.startswith(allowed + "/")


def classify(category: str, target: str, allowed_targets: list[str]) -> tuple[str, str]:
    """Return (decision, reason) where decision is allow, deny or pause."""
    cat = (category or "").strip().lower()
    if cat not in KNOWN:
        return "pause", f"unknown action category '{category}'. Ask Glow or Eric to clarify"
    if cat in UNAVAILABLE:
        return "deny", f"'{cat}' is not available in this pilot. Approval cannot enable it"
    if not (target or "").strip():
        return "pause", f"'{cat}' has no target. Ask Glow or Eric to name one"
    norm = normalize_target(target)
    if norm is None:
        return "deny", f"target '{target}' is not acceptable (empty or contains '..')"
    if any(covers(a, norm) for a in (normalize_target(x) for x in allowed_targets) if a):
        return "allow", "target is on Eric's allowed list"
    return "deny", f"target '{target}' is not on Eric's allowed list for '{cat}'"
