"""Wake Adapter with the v0.2 local Wake Transport.

Reads bridge_poller databases read-only and produces WakeEvent notifications (NOTIFICATION_ONLY). The v0.2
transport delivers them to a local outbox in %LOCALAPPDATA%\\MiniGlow and advances the checkpoint only when the
route's recipient explicitly acknowledges one event with its delivery code. Standard library only: no network,
no credentials, no Bridge or Drive writes, no packet text. Writes: the checkpoint, the outbox and the audit log.
"""
__version__ = "0.2"

from .classify import AdapterResult, produce
from .events import WakeEvent
from .outbox import LocalOutboxTransport
from .paths import Refused, Stopped
from .transport import Receipt, Transport, hand_over, validate_receipt

__all__ = ["AdapterResult", "LocalOutboxTransport", "Receipt", "Refused", "Stopped", "Transport", "WakeEvent",
           "hand_over", "produce", "validate_receipt"]
