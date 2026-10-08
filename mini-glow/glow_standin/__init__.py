"""Local stand-in for Glow, for testing the bridge link only. It is NOT the real Glow.

It answers PING packets from Claude-to-Glow with a reply in Glow-to-Claude, signed FROM: GLOW-STANDIN. The text
comes from the free local model (Ollama on 127.0.0.1) when available, else a fixed sentence. It never answers
WAKE_EVENT packets, and the bridge link refuses any stand-in reply to one. No purchases, no network beyond
loopback, no credentials.
"""
from .standin import respond

__all__ = ["respond"]
