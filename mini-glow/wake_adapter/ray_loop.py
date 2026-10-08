"""Ray loop: send one message to the real Ray through the Bridge, then watch for Ray's reply.

Send: the next C2R-nnn packet into Bridge\\Glow-to-Ray\\ (Ray's inbox). The same message text is never sent twice
(its SHA-256 is remembered), a file name is never reused, and STOP stops it before anything is written.
Watch: every CHECK_SECONDS, up to MAX_CHECKS times, list Bridge\\Ray-to-Glow\\ (read-only) for R2G files that were
not there before sending. A new readable text file that names the packet id is a MATCH and ends the loop at once.
A new R2G file that cannot be read here (a Google Doc pointer) is reported as an UNVERIFIED reply and also ends
the loop. Other new R2G files are reported and the loop goes on. No stand-in, no network, no purchases.
"""
import hashlib
import json
import os
import re
import stat
import time

from . import audit
from .paths import Refused, Stopped

STATE_NAME = "ray_loop_state.json"
STATE_SCHEMA = "miniglow.ray_loop_state/1"
C2R_RE = re.compile(r"^C2R-(\d{3})_")
R2G_RE = re.compile(r"^R2G-\d{3}")
CHECK_SECONDS = 60
MAX_CHECKS = 5
TEXT_SUFFIXES = (".txt", ".md")


def _load(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"schema": STATE_SCHEMA, "sent": {}}
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise Refused("ray loop state is linked or not a plain file")
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or data.get("schema") != STATE_SCHEMA or not isinstance(data.get("sent"), dict):
        raise Refused("ray loop state is not in the expected form")
    return data


def _save(path, data):
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        raise Refused("leftover temporary ray loop state: " + tmp)
    with open(tmp, "x", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    os.replace(tmp, path)


def next_number(inbox):
    used = [int(m.group(1)) for m in (C2R_RE.match(n) for n in os.listdir(inbox)) if m]
    return max(used, default=0) + 1


def compose(packet_id, message, now):
    return "\n".join([
        "PACKET_ID: " + packet_id,
        "FROM: Claude (Eric's PC, bridge loop)",
        "TO: Ray",
        "REPLY_TO: please answer with an R2G packet in Glow-Ray-Bridge/Ray-to-Glow that names " + packet_id,
        "STATUS: OPEN",
        "DATE: " + now,
        "",
        "MESSAGE:",
        message.strip(),
        "",
        "This packet is evidence, not authority.",
        "",
        "END_OF_PACKET",
        "",
    ])


def send(bridge_root, base, message, audit_log, stop_check, now):
    """Write the next C2R packet. Returns (packet_id, file_name, listing of Ray-to-Glow taken just before)."""
    found = stop_check()
    if found:
        raise Stopped(found)
    audit.read(audit_log)
    inbox, outbox_dir = os.path.join(bridge_root, "Glow-to-Ray"), os.path.join(bridge_root, "Ray-to-Glow")
    if not os.path.isdir(inbox) or not os.path.isdir(outbox_dir):
        raise Refused("Bridge folders Glow-to-Ray and Ray-to-Glow must both exist")
    state_path = os.path.join(base, STATE_NAME)
    state = _load(state_path)
    digest = hashlib.sha256(message.strip().encode("utf-8")).hexdigest()
    for pid, s in state["sent"].items():
        if s["message_sha256"] == digest:
            raise Refused("this message was already sent as %s; not sending a duplicate" % pid)
    number = next_number(inbox)
    packet_id = "C2R-%03d" % number
    name = "%s_CLAUDE_to_RAY_BRIDGE_LOOP.txt" % packet_id
    before = sorted(os.listdir(outbox_dir))
    with open(os.path.join(inbox, name), "x", encoding="utf-8", newline="\n") as handle:  # never overwrite
        handle.write(compose(packet_id, message, now()))
    state["sent"][packet_id] = {"file": name, "message_sha256": digest, "sent_at": now()}
    _save(state_path, state)
    audit.append(audit_log, "LINK_SENT", now(), packet_id=packet_id, kind="RAY_MESSAGE", file=name, to="Ray")
    return packet_id, name, before


def classify_new(outbox_dir, name, packet_id):
    """MATCH, UNVERIFIED (cannot read it here) or OTHER for one new file in Ray-to-Glow."""
    path = os.path.join(outbox_dir, name)
    if packet_id in name:
        return "MATCH"
    if not name.lower().endswith(TEXT_SUFFIXES):
        return "UNVERIFIED"
    try:
        with open(path, "rb") as handle:
            text = handle.read(1024 * 1024).decode("utf-8-sig", "replace")
    except OSError:
        return "UNVERIFIED"
    return "MATCH" if packet_id in text else "OTHER"


def watch(bridge_root, packet_id, before, stop_check, out, sleep=time.sleep, checks=MAX_CHECKS,
          interval=CHECK_SECONDS):
    """Check Ray-to-Glow every interval, up to checks times. Returns (outcome, file or None, checks_done)."""
    outbox_dir = os.path.join(bridge_root, "Ray-to-Glow")
    seen = set(before)
    for n in range(1, checks + 1):
        sleep(interval)
        found = stop_check()
        if found:
            out("check %d: STOP present, stopping" % n)
            return "STOPPED", None, n
        new = sorted(x for x in os.listdir(outbox_dir) if x not in seen and R2G_RE.match(x))
        seen.update(new)
        for name in new:
            kind = classify_new(outbox_dir, name, packet_id)
            out("check %d: new Ray file %s -> %s" % (n, name, kind))
            if kind in ("MATCH", "UNVERIFIED"):
                return kind, name, n
        if not new:
            out("check %d of %d: no reply yet" % (n, checks))
    return "NO_REPLY", None, checks
