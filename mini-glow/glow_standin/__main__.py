"""py -3.14 -B -m glow_standin [--no-model]   Answer unanswered PING packets in the Bridge (test stand-in only)."""
import sys

from wake_adapter.paths import BRIDGE_ROOT

from .standin import ollama_text, respond


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    written = respond(BRIDGE_ROOT, model_text=None if "--no-model" in argv else ollama_text)
    print("GLOW-STANDIN wrote %d reply(ies): %s" % (len(written), ", ".join(written) or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
