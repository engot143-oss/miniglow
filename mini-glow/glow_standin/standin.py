"""The stand-in's one job: answer each unanswered PING packet once."""
import json
import os
import re
import urllib.request
from datetime import datetime, timezone

from wake_adapter.bridge import END, OUT_NAME_RE, STANDIN_MARK, parse_packet

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"  # loopback only; fixed, never configurable
MODEL = "llama3.1:8b"
DEFAULT_TEXT = "Stand-in received the packet. This is an automatic test reply from Eric's PC, not the real Glow."
FORBIDDEN_LINE = re.compile(r"^\s*(ACK\b|END_OF_PACKET|PACKET_ID:|FROM:|TO:|REPLY_TO:|STATUS:|MESSAGE:|KIND:)", re.I)


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ollama_text(packet_text, timeout=120):
    """A short reply from the local model, or None if it is not available."""
    prompt = ("You are a local TEST stand-in for an assistant called Glow. You received this bridge test packet:\n\n"
              + packet_text[:4000] + "\n\nIn at most three sentences, confirm receipt and restate its MESSAGE in "
              "your own words. Do not write any line starting with ACK, and do not write packet headers.")
    body = json.dumps({"model": MODEL, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never through a proxy
    try:
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read(1024 * 1024).decode("utf-8")).get("response") or None
    except (OSError, ValueError):
        return None


def clean(text):
    """Model text with every line that could pose as an ACK or a packet header removed, and a length cap."""
    lines = [line for line in (text or "").splitlines() if not FORBIDDEN_LINE.match(line)]
    return "\n".join(lines).strip()[:1500] or DEFAULT_TEXT


def respond(bridge_root, model_text=ollama_text, now=utcnow):
    """Answer every complete, unanswered PING in Claude-to-Glow. Returns the reply file names written."""
    out_dir = os.path.join(bridge_root, "Claude-to-Glow")
    in_dir = os.path.join(bridge_root, "Glow-to-Claude")
    if not os.path.isdir(out_dir):
        return []
    os.makedirs(in_dir, exist_ok=True)
    answered = {n[4:8] for n in os.listdir(in_dir) if n.startswith("BL-G")}
    written = []
    for name in sorted(os.listdir(out_dir)):
        m = OUT_NAME_RE.match(name)
        if not m or m.group(1) in answered:
            continue
        with open(os.path.join(out_dir, name), "rb") as handle:
            text = handle.read(256 * 1024).decode("utf-8", "replace")
        fields = parse_packet(text)
        if not fields or fields.get("KIND:") != "PING" or not fields.get("ACK_REF:") or not fields.get("ACK_CODE:"):
            continue
        number, packet_id = m.group(1), fields["PACKET_ID:"]
        message = clean(model_text(text) if model_text else None)
        reply = "\n".join([
            "PACKET_ID: BL-G" + number,
            "FROM: %s (local model on Eric's PC, NOT the real Glow)" % STANDIN_MARK,
            "TO: Claude",
            "REPLY_TO: " + packet_id,
            "STATUS: REPLY",
            "DATE: " + now(),
            "",
            "MESSAGE:",
            message,
            "",
            "ACK %s %s" % (fields["ACK_REF:"], fields["ACK_CODE:"]),
            END,
            "",
        ])
        reply_name = "BL-G%s_STANDIN_REPLY.txt" % number
        fd = os.open(os.path.join(in_dir, reply_name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                     0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(reply.encode("utf-8"))
        written.append(reply_name)
    return written
