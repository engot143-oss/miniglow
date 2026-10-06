"""Filename and completeness rules for Ray-to-Glow packets (R2G-nnn)."""
import re

NAME_RE = re.compile(r"^(R2G-\d{3})_")
REQUIRED_HEADERS = ("PACKET_ID:", "FROM:", "TO:", "REPLY_TO:", "STATUS:")
END_MARKER = "END_OF_PACKET"
BOM = "\ufeff"


def _clean(text):
    """Drop a leading byte-order mark, so a packet saved by a BOM-writing editor still counts."""
    return (text or "").lstrip(BOM)


def packet_id_from_name(name):
    """Return 'R2G-005' for 'R2G-005_...txt', else None."""
    match = NAME_RE.match(name or "")
    return match.group(1) if match else None


def header_packet_id(text):
    """Value of the first PACKET_ID: line, or None."""
    for line in _clean(text).splitlines():
        if line.startswith("PACKET_ID:"):
            return line[len("PACKET_ID:"):].strip()
    return None


def is_complete(text):
    """True only if headers, a non-empty body, and the END_OF_PACKET line are all present."""
    text = _clean(text)
    if not text or not text.strip():
        return False
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines or lines[-1].strip() != END_MARKER:
        return False
    for key in REQUIRED_HEADERS:
        if not any(line.startswith(key) for line in lines):
            return False
    idx = next((i for i, line in enumerate(lines) if line.startswith("MESSAGE:")), None)
    if idx is None:
        return False
    inline = lines[idx][len("MESSAGE:"):].strip()
    body_lines = lines[idx + 1:-1]
    return bool(inline or body_lines)
