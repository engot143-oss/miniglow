"""Bridge folder identifiers as configuration, not logic.

Precedence: command-line value, then environment variable, then the known default.
The IDs are identifiers, not secrets. Standard library only.
"""
import os

DEFAULT_FOLDER_ID = "1CIQ4F-nXR_N6SOr_rPB4qm0HTwqrINEA"  # Ray-to-Glow
DEFAULT_ROOT_ID = "1shjWGaRUvoahNb72hkI2Hez0qn7Kzj_i"  # Glow-Ray-Bridge (STOP file lives here)
ENV_FOLDER_ID = "BRIDGE_POLLER_FOLDER_ID"
ENV_ROOT_ID = "BRIDGE_POLLER_ROOT_ID"
ENV_FOLDER_PATH = "BRIDGE_POLLER_FOLDER_PATH"  # local Ray-to-Glow folder (no default)
ENV_ROOT_PATH = "BRIDGE_POLLER_ROOT_PATH"  # local Bridge root folder (no default)
ENV_DB = "BRIDGE_POLLER_DB"
ENV_KEY_FILE = "BRIDGE_POLLER_KEY_FILE"  # service-account key for --live-api (no default; never in the repo)


def _pick(cli_value, env_name, default, environ):
    if cli_value:
        return cli_value
    env_value = (environ.get(env_name) or "").strip()
    return env_value or default


def resolve_ids(cli_folder=None, cli_root=None, environ=None):
    """Return (folder_id, root_id)."""
    environ = os.environ if environ is None else environ
    return (
        _pick(cli_folder, ENV_FOLDER_ID, DEFAULT_FOLDER_ID, environ),
        _pick(cli_root, ENV_ROOT_ID, DEFAULT_ROOT_ID, environ),
    )


def resolve_paths(cli_folder=None, cli_root=None, environ=None):
    """Return (folder_path, root_path) for a local copy; None when not configured. No defaults."""
    environ = os.environ if environ is None else environ
    return (
        _pick(cli_folder, ENV_FOLDER_PATH, None, environ),
        _pick(cli_root, ENV_ROOT_PATH, None, environ),
    )


def resolve_key_file(cli_value=None, environ=None):
    """Path of the service-account key file, or None when not configured. No default."""
    environ = os.environ if environ is None else environ
    return _pick(cli_value, ENV_KEY_FILE, None, environ)


def default_db(environ=None, platform=None):
    """Absolute database path outside the repository and outside any watched folder."""
    environ = os.environ if environ is None else environ
    platform = os.name if platform is None else platform
    chosen = _pick(None, ENV_DB, None, environ)
    if chosen:
        return chosen
    if platform == "nt":
        base = environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        return os.path.join(base, "MiniGlow", "bridge_poller.sqlite")
    return os.path.join(os.path.expanduser("~"), ".local", "state", "miniglow", "bridge_poller.sqlite")
