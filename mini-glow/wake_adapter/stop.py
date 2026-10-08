"""STOP gate. Same rule as Mini Ray (mini_ray/context.py Context.stop_present), kept as an independent copy.

Stricter than bridge_poller's own check (an exact file named STOP): any name starting with STOP in the
Bridge root, any MINIRAY_STOP* in the MiniGlow folder, or an unreachable Bridge root all count as STOP.
"""
import os


def stop_present(bridge_root, base):
    """List of reasons to stop; empty when it is safe to go on. Reads folder listings only."""
    found = []
    try:
        names = os.listdir(bridge_root)
    except OSError:
        return ["Bridge root unreachable: " + bridge_root]
    found += [os.path.join(bridge_root, n) for n in sorted(names) if n.upper().startswith("STOP")]
    try:
        local = os.listdir(base)
    except OSError:
        local = []
    found += [os.path.join(base, n) for n in sorted(local) if n.upper().startswith("MINIRAY_STOP")]
    return found
