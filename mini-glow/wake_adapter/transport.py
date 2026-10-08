"""Boundary to a future transport. v0.1 defines the contract only; no transport is implemented here.

Contract for any transport:
1. Run STOP gate #3 before delivering anything; with STOP present, confirm nothing.
2. Deliver only events whose route is in its own routes.
3. Never change an event.
4. A partial confirmation is allowed. If deliver() raises, nothing counts as confirmed.
Delivery is at-least-once: only ids in Receipt.confirmed advance the checkpoint; everything else stays
eligible for retry, so the receiver must deduplicate (packet_id + drive_file_id, then event_id).
"""
import hashlib
from dataclasses import dataclass
from typing import Protocol, Sequence

from .events import WakeEvent
from .paths import Refused, Stopped


class Transport(Protocol):
    name: str
    routes: frozenset  # for example frozenset({"GLOW"}) or frozenset({"ERIC"})

    def deliver(self, events: Sequence[WakeEvent]) -> "Receipt": ...


@dataclass(frozen=True)
class Receipt:
    transport: str
    batch_id: str  # sha256 of the sorted event_ids that were handed over
    confirmed: tuple  # event_ids the receiver acknowledged
    failed: tuple  # (event_id, reason) pairs
    confirmed_at: str


def batch_id(events):
    return hashlib.sha256("\n".join(sorted(e.event_id for e in events)).encode("utf-8")).hexdigest()


def _ids(values, label):
    if not isinstance(values, tuple) or not all(isinstance(v, str) for v in values):
        raise Refused("receipt %s must be a tuple of event ids" % label)
    if len(set(values)) != len(values):
        raise Refused("receipt lists an event id twice in " + label)
    return set(values)


def validate_receipt(events, receipt):
    """Return the confirmed event ids, or raise Refused if the receipt does not fit this exact batch."""
    if not isinstance(receipt, Receipt):
        raise Refused("not a Receipt")
    if not (isinstance(receipt.transport, str) and receipt.transport and isinstance(receipt.confirmed_at, str)):
        raise Refused("receipt without transport name or time")
    ids = [e.event_id for e in events]
    if len(set(ids)) != len(ids):
        raise Refused("the batch holds the same event twice")
    if receipt.batch_id != batch_id(events):
        raise Refused("receipt is for a different batch")
    confirmed = _ids(receipt.confirmed, "confirmed")
    if not isinstance(receipt.failed, tuple) or not all(
            isinstance(f, tuple) and len(f) == 2 and all(isinstance(x, str) for x in f) for f in receipt.failed):
        raise Refused("receipt failed must be a tuple of (event_id, reason)")
    failed = _ids(tuple(f[0] for f in receipt.failed), "failed")
    if (confirmed | failed) - set(ids):
        raise Refused("receipt names an event that was not in the batch")
    if confirmed & failed:
        raise Refused("receipt marks an event both confirmed and failed")
    return confirmed


def hand_over(transport, events, stop_check):
    """Adapter side of the boundary: STOP gate #3 and the route check, then deliver and validate the receipt."""
    found = stop_check()
    if found:
        raise Stopped(found)
    wrong = sorted({e.route for e in events} - set(transport.routes))
    if wrong:
        raise Refused("transport %s does not serve route(s): %s" % (transport.name, ", ".join(wrong)))
    events = tuple(events)
    receipt = transport.deliver(events)
    validate_receipt(events, receipt)
    return receipt
