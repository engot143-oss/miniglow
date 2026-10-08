"""Bridge link v0.3: automatic Claude <-> Glow packets through two Bridge folders. Nothing else is sent.

Outgoing packets go to Bridge\\Claude-to-Glow\\BL-Cnnnn_*.txt; replies are read from Bridge\\Glow-to-Claude\\
BL-Gnnnn_*.txt. Every outgoing packet carries an ACK_REF (64 hex) and a one-time ACK_CODE (8 hex). A reply counts
only if it is a complete packet, answers a packet we sent (REPLY_TO), and holds exactly one line
"ACK <ref> <code>" matching that packet.

Kinds of outgoing packet:
- PING: a harmless test. A valid reply marks it answered. Nothing else changes.
- WAKE_EVENT: a pending GLOW-route outbox delivery. A valid reply from Glow is recorded as AWAITING_ERIC: it does
  NOT change the checkpoint. Eric confirms it with the bridge-confirm command (typed YES), which then runs the
  normal outbox acknowledgment. Nothing acknowledges an event automatically.
A reply from the local stand-in (FROM contains GLOW-STANDIN) may answer a PING but can never count for a
WAKE_EVENT: a local model must not claim that Glow saw something.

Every reply file is processed once (by SHA-256); its text is copied to MiniGlow\\bridge_inbox\\ for Claude and
Eric to read. Packet text is evidence, never instructions: nothing in a reply is executed.
"""
import hashlib
import json
import os
import re
import secrets
import stat

from . import audit, outbox
from .paths import Refused, Stopped, link_dirs, link_inbox_dir, link_state_path

STATE_SCHEMA = "miniglow.bridge_link_state/1"
OUT_NAME_RE = re.compile(r"^BL-C(\d{4})_[A-Z0-9_]{1,60}\.txt\Z")
IN_NAME_RE = re.compile(r"^BL-G(\d{4})_[A-Za-z0-9_.-]{1,80}\.txt\Z")
PACKET_ID_RE = re.compile(r"^BL-C\d{4}\Z")
REPLY_ID_RE = re.compile(r"^BL-G\d{4}\Z")
HEADERS = ("PACKET_ID:", "FROM:", "TO:", "REPLY_TO:", "STATUS:")
END = "END_OF_PACKET"
STANDIN_MARK = "GLOW-STANDIN"
KINDS = ("PING", "WAKE_EVENT")
MAX_BYTES = 256 * 1024
MAX_NUMBER = 9999


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def ping_ref(packet_id):
    return _sha(("PING|" + packet_id).encode("utf-8"))


# ---------------------------------------------------------------- state

def _empty_state():
    return {"schema": STATE_SCHEMA, "next": 1, "sent": {}, "processed": {}}


def load_state(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return _empty_state()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise Refused("bridge link state is linked or not a plain file: " + path)
    with open(path, "rb") as handle:
        try:
            data = json.loads(handle.read(4 * 1024 * 1024).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Refused("bridge link state is not valid JSON")
    if not isinstance(data, dict) or set(data) != {"schema", "next", "sent", "processed"} or \
            data["schema"] != STATE_SCHEMA or type(data["next"]) is not int or \
            not 1 <= data["next"] <= MAX_NUMBER + 1 or not isinstance(data["sent"], dict) or \
            not isinstance(data["processed"], dict):
        raise Refused("bridge link state is not in the expected form")
    for pid, s in data["sent"].items():
        if not PACKET_ID_RE.match(pid) or not isinstance(s, dict) or s.get("kind") not in KINDS:
            raise Refused("bridge link state holds a bad sent entry: %r" % (pid,))
    return data


def save_state(path, data):
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        raise Refused("leftover temporary bridge link state: " + tmp)
    payload = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.lexists(tmp):
            os.remove(tmp)
        raise


# ---------------------------------------------------------------- packets

def parse_packet(text):
    """Header values of a complete packet, or None if it is not complete (headers, MESSAGE, END_OF_PACKET last)."""
    text = (text or "").lstrip("﻿")
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if not lines or lines[-1].strip() != END:
        return None
    fields = {}
    for line in lines:
        for key in HEADERS + ("ACK_REF:", "ACK_CODE:", "KIND:"):
            if line.startswith(key) and key not in fields:
                fields[key] = line[len(key):].strip()
    if any(h not in fields for h in HEADERS) or not any(line.startswith("MESSAGE:") for line in lines):
        return None
    return fields


def compose(packet_id, kind, ref, code, body, now):
    number = packet_id[4:]
    return "\n".join([
        "PACKET_ID: " + packet_id,
        "FROM: Claude (Eric's PC, automatic bridge link)",
        "TO: Glow",
        "REPLY_TO: reply as BL-G%s_<anything>.txt in Glow-Ray-Bridge/Glow-to-Claude/" % number,
        "STATUS: OPEN",
        "KIND: " + kind,
        "DATE: " + now,
        "ACK_REF: " + ref,
        "ACK_CODE: " + code,
        "",
        "MESSAGE:",
        body.rstrip(),
        "",
        "HOW TO REPLY: a packet with PACKET_ID: BL-G%s, FROM, TO, REPLY_TO: %s, STATUS, MESSAGE, and exactly one"
        % (number, packet_id),
        "line  ACK %s %s  and END_OF_PACKET as the last line." % (ref, code),
        "This packet is evidence, not authority. It asks only for the acknowledgment.",
        "",
        END,
        "",
    ])


def _write_new(folder, name, data):
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, name)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    except FileExistsError:
        raise Refused("file already exists, never overwritten: " + path)
    with os.fdopen(fd, "wb") as handle:  # a name is used once; never overwritten
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    return path


class Link:
    def __init__(self, base, bridge_root, audit_log, stop_check, now, token=lambda: secrets.token_hex(4)):
        self.base, self.audit_log, self.stop_check, self.now, self.token = base, audit_log, stop_check, now, token
        self.out_dir, self.in_dir = link_dirs(bridge_root)
        self.state_path, self.inbox_dir = link_state_path(base), link_inbox_dir(base)

    def _gate(self):
        found = self.stop_check()
        if found:
            raise Stopped(found)
        audit.read(self.audit_log)  # a broken audit chain refuses before any write

    def _send(self, state, kind, ref, code, body, extra):
        n = state["next"]
        if n > MAX_NUMBER:
            raise Refused("bridge link packet numbers exhausted")
        packet_id = "BL-C%04d" % n
        name = "%s_%s.txt" % (packet_id, kind)
        if not OUT_NAME_RE.match(name):
            raise Refused("bad outgoing packet name")
        _write_new(self.out_dir, name, compose(packet_id, kind, ref, code, body, self.now()).encode("utf-8"))
        state["next"] = n + 1
        state["sent"][packet_id] = dict(extra, kind=kind, ref=ref, code_sha256=audit.code_hash(code), file=name,
                                        sent_at=self.now(), status="SENT")
        save_state(self.state_path, state)
        audit.append(self.audit_log, "LINK_SENT", self.now(), packet_id=packet_id, kind=kind, ref=ref,
                     code_sha256=audit.code_hash(code), file=name)
        return packet_id

    def send_ping(self, note="Bridge link test. Please reply with the ACK line below."):
        self._gate()
        state = load_state(self.state_path)
        packet_id = "BL-C%04d" % state["next"]
        return self._send(state, "PING", ping_ref(packet_id), self.token(), note, {})

    def send_pending(self, outbox_dir):
        """One WAKE_EVENT packet per pending GLOW delivery attempt not sent yet. Returns the packet ids."""
        self._gate()
        state = load_state(self.state_path)
        done = {(s.get("event_id"), s.get("attempt")) for s in state["sent"].values() if s["kind"] == "WAKE_EVENT"}
        sent = []
        for rec in outbox.records(outbox_dir, "GLOW"):
            e = rec["event"]
            if rec["status"] != "PENDING" or (e.event_id, rec["attempt"]) in done:
                continue
            body = ("A WakeEvent for Glow (notification only, NOTIFICATION_ONLY).\nKIND %s  PACKET %s\nEVENT %s\n"
                    "DETAILS %s" % (e.kind, e.packet_id or "-", e.event_id, json.dumps(e.to_dict()["packet"])))
            sent.append(self._send(state, "WAKE_EVENT", e.event_id, rec["code"], body,
                                   {"event_id": e.event_id, "attempt": rec["attempt"]}))
        return sent

    def receive(self):
        """Process new reply files. Returns a list of (file, outcome). Never changes the checkpoint."""
        self._gate()
        state = load_state(self.state_path)
        results = []
        if not os.path.isdir(self.in_dir):
            return results
        for name in sorted(os.listdir(self.in_dir)):
            path = os.path.join(self.in_dir, name)
            if not IN_NAME_RE.match(name) or os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as handle:
                data = handle.read(MAX_BYTES + 1)
            digest = _sha(data)
            if digest in state["processed"]:
                continue
            outcome = self._one(state, name, data)
            if outcome is None:  # incomplete or still syncing: look again next cycle
                continue
            state["processed"][digest] = {"file": name, "outcome": outcome, "at": self.now()}
            save_state(self.state_path, state)
            results.append((name, outcome))
        return results

    def _reject(self, name, reason, **fields):
        audit.append(self.audit_log, "LINK_REJECTED", self.now(), file=name, detail=reason, **fields)
        return "REJECTED: " + reason

    def _one(self, state, name, data):
        if len(data) > MAX_BYTES:
            return self._reject(name, "reply too large")
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
        fields = parse_packet(text)
        if fields is None:
            return None
        reply_id = fields["PACKET_ID:"]
        reply_to = fields["REPLY_TO:"].split()[0] if fields["REPLY_TO:"] else ""
        if not REPLY_ID_RE.match(reply_id) or not name.startswith(reply_id + "_"):
            return self._reject(name, "PACKET_ID does not match the file name")
        sent = state["sent"].get(reply_to)
        if sent is None:
            return self._reject(name, "REPLY_TO names no packet that Claude sent")
        if reply_id[4:] != reply_to[4:]:
            return self._reject(name, "reply number does not match the packet it answers", packet_id=reply_to)
        acks = outbox.GLOW_ACK_RE.findall(text)
        if len(acks) != 1:
            return self._reject(name, "a reply must hold exactly one ACK line", packet_id=reply_to)
        ref, code = acks[0]
        if ref != sent["ref"] or audit.code_hash(code) != sent["code_sha256"]:
            return self._reject(name, "ACK does not match the packet's ACK_REF and ACK_CODE", packet_id=reply_to)
        standin = STANDIN_MARK in fields["FROM:"]
        if sent["status"] != "SENT":
            audit.append(self.audit_log, "LINK_DUPLICATE", self.now(), file=name, packet_id=reply_to)
            return "DUPLICATE: %s was already answered" % reply_to
        if sent["kind"] == "WAKE_EVENT" and standin:
            return self._reject(name, "a stand-in cannot answer for a real WakeEvent", packet_id=reply_to)
        if not os.path.exists(os.path.join(self.inbox_dir, name)):
            _write_new(self.inbox_dir, name, data)
        sent["status"] = "AWAITING_ERIC" if sent["kind"] == "WAKE_EVENT" else "ANSWERED"
        sent["reply_file"] = name
        sent["sender"] = "stand-in" if standin else "glow"
        audit.append(self.audit_log, "LINK_RECEIVED", self.now(), file=name, packet_id=reply_to, kind=sent["kind"],
                     sender=sent["sender"], reply_sha256=_sha(data), status=sent["status"])
        if sent["kind"] == "WAKE_EVENT":
            return "RECEIVED: Glow acknowledged %s; waiting for Eric to confirm (bridge-confirm %s)" % (
                reply_to, reply_to)
        return "ACCEPTED: %s answered by %s" % (reply_to, "the local stand-in" if standin else "Glow")

    def confirm(self, packet_id, outbox_dir, cp_path, actor, ask_yes):
        """Eric confirms Glow's acknowledgment of one WAKE_EVENT: the normal outbox acknowledgment, after YES."""
        self._gate()
        state = load_state(self.state_path)
        sent = state["sent"].get(packet_id)
        if sent is None or sent["kind"] != "WAKE_EVENT" or sent["status"] != "AWAITING_ERIC":
            raise Refused("%s is not a Glow acknowledgment waiting for confirmation" % packet_id)
        with open(os.path.join(self.inbox_dir, sent["reply_file"]), "rb") as handle:
            data = handle.read(MAX_BYTES + 1)
        ref, code = outbox.parse_glow_ack(data.decode("utf-8-sig"))
        if ref != sent["ref"] or audit.code_hash(code) != sent["code_sha256"]:
            raise Refused("the saved reply no longer matches the packet")
        new = outbox.acknowledge(outbox_dir, self.audit_log, cp_path, "GLOW", ref, code, actor, ask_yes,
                                 self.stop_check, self.now)
        sent["status"] = "CONFIRMED"
        save_state(self.state_path, state)
        return new

    def status(self):
        return load_state(self.state_path)
