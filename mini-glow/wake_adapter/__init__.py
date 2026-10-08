"""Wake Adapter v0.1 (staging). Reads bridge_poller databases read-only and produces WakeEvent notifications.

Standard library only. No network, no credentials, no Bridge or Drive writes, no packet text, no transport.
Its only persistent write is its own checkpoint in %LOCALAPPDATA%\\MiniGlow, advanced from a confirmed receipt.
"""
__version__ = "0.1"

from .classify import AdapterResult, produce
from .events import WakeEvent
from .paths import Refused, Stopped
from .transport import Receipt, Transport, hand_over, validate_receipt

__all__ = ["AdapterResult", "Receipt", "Refused", "Stopped", "Transport", "WakeEvent",
           "hand_over", "produce", "validate_receipt"]
