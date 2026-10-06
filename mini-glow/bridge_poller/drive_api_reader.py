"""Read-only Google Drive API reader for the Bridge (Phase 3, candidate 3, design A1).

A service account that has been shared as Viewer on the Bridge folder reads Ray-to-Glow
and checks the Bridge root for STOP. Every request goes through GuardedHttp, which only
allows GET requests to the Drive files endpoint and one POST to the Google token endpoint.
There is no call anywhere in this module that changes anything in Drive.

Any problem (bad key file, network, lost access, unexpected reply) raises ReaderError,
which ends the run as ERROR (fail-closed). Standard library only, except that signing the
token request needs the google-auth package; it is imported only when a real key is used.
"""
import base64
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .drive_reader import DriveReader
from .local_reader import ReaderError

DRIVE_HOST = "www.googleapis.com"
DRIVE_PATH = "/drive/v3/files"
DRIVE_FILES = "https://" + DRIVE_HOST + DRIVE_PATH
TOKEN_URI = "https://oauth2.googleapis.com/token"
TOKEN_CONTENT_TYPE = "application/x-www-form-urlencoded"
SCOPE = "https://www.googleapis.com/auth/drive.readonly"
TEXT_MIME = "text/plain"
MAX_BYTES = 5 * 1024 * 1024
MAX_PAGES = 20
MAX_KEY_BYTES = 20000
MAX_TOKEN_SECONDS = 3600
TIMEOUT_SECONDS = 30
ID_RE = re.compile(r"^[A-Za-z0-9_-]{10,200}\Z")
TOKEN_RE = re.compile(r"^[\x21-\x7e]{1,4096}\Z")  # printable ASCII, no spaces or line breaks
URL_RE = re.compile(r"^[\x21-\x7e]+\Z")
MIN_TOKEN_SECONDS = 120
LIST_QUERY_KEYS = frozenset({"q", "fields", "pageSize", "spaces", "pageToken"})
# Folder-name starts that mean "synced to the cloud" (matched on every folder in the key path, lower case).
SYNC_MARKERS = ("google drive", "googledrive", "my drive", "shared drives", "other computers", "onedrive",
                "dropbox", "icloud", "box sync", "meine ablage", "mi unidad", "mon disque", "il mio drive",
                "meu drive", "mijn drive")
SYNC_EXACT = ("box",)  # whole folder name only (so "boxes" is not refused)


def _check_id(value, label):
    if not isinstance(value, str) or not ID_RE.match(value):
        raise ReaderError(label + " is not a valid Drive ID")
    return value


# ---------------------------------------------------------------- key file

def _repo_root(start):
    """Nearest folder at or above start that contains .git, or None."""
    path = os.path.realpath(start)
    while True:
        if os.path.exists(os.path.join(path, ".git")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent


def _synced_folders(environ):
    found = []
    for name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        value = (environ.get(name) or "").strip()
        if value:
            found.append(value)
    return found


def _is_unc(path):
    return path.startswith("\\\\") or path.startswith("//")


def _inside(path, folder, pathmod=os.path):
    """True/False, or None when the two paths cannot be compared.

    Paths on two different drive letters are simply "not inside" (False). Any other failed
    comparison is None, which the key checks treat as unsafe.
    """
    path, folder = pathmod.normcase(pathmod.realpath(path)), pathmod.normcase(pathmod.realpath(folder))
    try:
        return pathmod.commonpath([path, folder]) == folder
    except ValueError:
        drive_a, drive_b = pathmod.splitdrive(path)[0], pathmod.splitdrive(folder)[0]
        if len(drive_a) == 2 and len(drive_b) == 2 and drive_a != drive_b:  # e.g. "c:" vs "d:"
            return False
        return None


def check_key_location(path, environ=None, package_dir=None, platform=None):
    """Refuse a key file in an unsafe place. On Windows the key must be under %LOCALAPPDATA%.

    A key on another drive letter than a folder is simply not inside it. Any other comparison that
    cannot be made (for example against a network path) is treated as unsafe and refused.
    """
    environ = os.environ if environ is None else environ
    platform = os.name if platform is None else platform
    package_dir = package_dir or os.path.dirname(os.path.abspath(__file__))
    if _is_unc(str(path)):
        raise ReaderError("the key file must not be on a network path")
    real = os.path.realpath(path)
    if _is_unc(real):
        raise ReaderError("the key file must not be on a network path")
    repo = _repo_root(package_dir)
    if repo and _inside(real, repo) is not False:
        raise ReaderError("the key file must not be inside the repository")
    if _inside(real, package_dir) is not False:
        raise ReaderError("the key file must not be inside the bridge_poller folder")
    for folder in _synced_folders(environ):
        if _inside(real, folder) is not False:
            raise ReaderError("the key file must not be inside a synced folder")
    for segment in real.replace("\\", "/").lower().split("/")[:-1]:
        segment = segment.strip()
        if segment.startswith(SYNC_MARKERS) or segment in SYNC_EXACT:
            raise ReaderError("the key file must not be inside a synced folder")
    if platform == "nt":
        local = (environ.get("LOCALAPPDATA") or "").strip()
        if not local or _inside(real, local) is not True:
            raise ReaderError("on Windows the key file must be inside %LOCALAPPDATA%")
    return real


def load_key_file(path, environ=None, package_dir=None, platform=None):
    """Read and check a service-account key file. Returns the parsed key information."""
    if not path:
        raise ReaderError("no key file configured")
    real = check_key_location(path, environ, package_dir, platform)
    if not os.path.isfile(real):
        raise ReaderError("key file is missing: " + path)
    if os.path.getsize(real) > MAX_KEY_BYTES:
        raise ReaderError("key file is too large to be a service-account key")
    try:
        with open(real, "r", encoding="utf-8") as handle:
            info = json.load(handle)
    except (OSError, ValueError) as err:
        raise ReaderError("key file cannot be read as JSON: %s" % err.__class__.__name__)
    if not isinstance(info, dict) or info.get("type") != "service_account":
        raise ReaderError("key file is not a service-account key")
    for field in ("client_email", "private_key", "token_uri"):
        if not isinstance(info.get(field), str) or not info.get(field):
            raise ReaderError("key file is missing " + field)
    if info["token_uri"] != TOKEN_URI:
        raise ReaderError("key file names an unexpected token address")
    return info


def google_auth_signer(info):
    """Build an RS256 signer from the key (needs google-auth; imported only here)."""
    try:
        from google.auth import crypt  # third-party, pinned in requirements-live.txt
    except ImportError:
        raise ReaderError("google-auth is not installed; see requirements-live.txt")
    try:
        signer = crypt.RSASigner.from_service_account_info(info)
    except Exception as err:  # bad private key format
        raise ReaderError("key file private key cannot be used: %s" % err.__class__.__name__)
    return signer.sign


# ---------------------------------------------------------------- HTTP

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: a 3xx reply comes back as an error, so no request leaves the guard."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibHttp:
    """Real network access with a timeout and no redirects. Returns (status, body_bytes)."""

    def __init__(self):
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(self, method, url, headers, body=None):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=TIMEOUT_SECONDS) as resp:
                return resp.status, resp.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as err:
            try:
                return err.code, b""
            finally:
                err.close()
        except (urllib.error.URLError, http.client.HTTPException, OSError) as err:
            raise ReaderError("network problem: %s" % err.__class__.__name__)


def _drive_get_allowed(url, headers):
    if not isinstance(url, str) or not URL_RE.match(url):
        return False  # no spaces, tabs, line breaks or other hidden characters
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc != DRIVE_HOST or parts.fragment:
        return False
    auth = headers.get("Authorization", "")
    if set(headers) != {"Authorization"} or not auth.startswith("Bearer ") or not TOKEN_RE.match(auth[7:]):
        return False
    try:
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return False
    keys = [k for k, _v in pairs]
    if len(keys) != len(set(keys)):
        return False
    if parts.path == DRIVE_PATH:
        return bool(keys) and set(keys) <= LIST_QUERY_KEYS
    prefix = DRIVE_PATH + "/"
    if parts.path.startswith(prefix) and ID_RE.match(parts.path[len(prefix):]):
        return pairs == [("alt", "media")]
    return False


def _token_post_allowed(url, headers, body):
    return url == TOKEN_URI and headers == {"Content-Type": TOKEN_CONTENT_TYPE} and isinstance(body, bytes)


class GuardedHttp:
    """Allows only GET to the Drive files endpoint and POST to the token endpoint.

    The URL is parsed: exact host and path, a file ID that matches ID_RE, allowlisted
    query keys, and exact headers. A redirect reply is refused, never followed.
    """

    def __init__(self, inner):
        self.inner = inner

    def request(self, method, url, headers, body=None):
        headers = dict(headers or {})
        if method == "GET" and body is None and _drive_get_allowed(url, headers):
            reply = self.inner.request(method, url, headers, None)
        elif method == "POST" and _token_post_allowed(url, headers, body):
            reply = self.inner.request(method, url, headers, body)
        else:
            raise ReaderError("refused request: %s %s" % (method, str(url).split("?")[0]))
        if 300 <= reply[0] < 400:
            raise ReaderError("refused redirect (HTTP %d)" % reply[0])
        return reply


def _status_error(status, what):
    if status in (401, 403):
        return ReaderError("access lost while %s (HTTP %d)" % (what, status))
    if status == 404:
        return ReaderError("not found while %s (HTTP 404)" % what)
    if status == 429 or status >= 500:
        return ReaderError("Drive unavailable while %s (HTTP %d)" % (what, status))
    return ReaderError("unexpected reply while %s (HTTP %d)" % (what, status))


# ---------------------------------------------------------------- token

def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


class TokenSource:
    """Short-lived read-only access token for the service account."""

    def __init__(self, info, http, sign, now=time.time):
        self.info, self.http, self.sign, self.now = info, http, sign, now
        self.token, self.expires = None, 0

    def get(self):
        if self.token and self.now() < self.expires - 60:
            return self.token
        issued = int(self.now())
        header = {"alg": "RS256", "typ": "JWT"}
        if self.info.get("private_key_id"):
            header["kid"] = self.info["private_key_id"]
        claims = {"iss": self.info["client_email"], "scope": SCOPE, "aud": TOKEN_URI,
                  "iat": issued, "exp": issued + 3600}
        unsigned = _b64(json.dumps(header, separators=(",", ":")).encode()) + b"." + \
            _b64(json.dumps(claims, separators=(",", ":")).encode())
        assertion = unsigned + b"." + _b64(self.sign(unsigned))
        body = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion.decode("ascii"),
        }).encode("ascii")
        status, data = self.http.request("POST", TOKEN_URI, {"Content-Type": TOKEN_CONTENT_TYPE}, body)
        if status != 200:
            raise _status_error(status, "requesting a token")
        try:
            reply = json.loads(data.decode("utf-8"))
            token, lifetime = reply["access_token"], reply.get("expires_in", MAX_TOKEN_SECONDS)
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ReaderError("token reply could not be understood")
        if not isinstance(token, str) or not TOKEN_RE.match(token):
            raise ReaderError("token reply had no usable token")
        if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime < MIN_TOKEN_SECONDS:
            raise ReaderError("token reply had no usable lifetime")
        self.token, self.expires = token, issued + min(lifetime, MAX_TOKEN_SECONDS)
        return token


# ---------------------------------------------------------------- reader

class ApiReader(DriveReader):
    def __init__(self, folder_id, root_id, token_source, http):
        self.folder_id = _check_id(folder_id, "Ray-to-Glow folder ID")
        self.root_id = _check_id(root_id, "Bridge root ID")
        if self.folder_id == self.root_id:
            raise ReaderError("Ray-to-Glow folder and Bridge root must be different")
        self._tokens = token_source
        self._http = GuardedHttp(http)
        self._sizes = {}  # file id -> size, only for files seen in a listing
        self.ignored = 0  # files skipped because of type or parent

    def _get_json(self, params, what):
        url = DRIVE_FILES + "?" + urllib.parse.urlencode(params)
        status, data = self._http.request(
            "GET", url, {"Authorization": "Bearer " + self._tokens.get()})
        if status != 200:
            raise _status_error(status, what)
        try:
            reply = json.loads(data.decode("utf-8"))
        except ValueError:
            raise ReaderError("Drive reply could not be understood while " + what)
        if not isinstance(reply, dict):
            raise ReaderError("Drive reply was not an object while " + what)
        return reply

    def _list(self, query, fields, what):
        files, page_token = [], None
        for _ in range(MAX_PAGES):
            params = {"q": query, "fields": "nextPageToken,files(" + fields + ")",
                      "pageSize": "100", "spaces": "drive"}
            if page_token:
                params["pageToken"] = page_token
            reply = self._get_json(params, what)
            page = reply.get("files")
            if not isinstance(page, list) or not all(isinstance(f, dict) for f in page):
                raise ReaderError("Drive reply had no proper file list while " + what)
            files.extend(page)
            page_token = reply.get("nextPageToken")
            if page_token is not None and not isinstance(page_token, str):
                raise ReaderError("Drive reply had a bad page token while " + what)
            if not page_token:
                return files
        raise ReaderError("too many pages while " + what + "; listing treated as incomplete")

    def list_folder(self, folder_id):
        if folder_id != self.folder_id:
            raise ReaderError("Ray-to-Glow ID requested by the poller does not match the configured ID")
        query = "'%s' in parents and mimeType = '%s' and trashed = false" % (self.folder_id, TEXT_MIME)
        listing, self.ignored = [], 0
        for f in self._list(query, "id,name,mimeType,createdTime,size,parents", "listing Ray-to-Glow"):
            try:
                fid = _check_id(f.get("id"), "file ID")
            except ReaderError:
                self.ignored += 1
                continue
            parents = f.get("parents")
            if f.get("mimeType") != TEXT_MIME or not isinstance(parents, list) or self.folder_id not in parents:
                self.ignored += 1
                continue
            try:
                size = int(f.get("size", "0"))
            except (TypeError, ValueError):
                size = MAX_BYTES + 1
            self._sizes[fid] = size
            listing.append({"id": fid, "name": str(f.get("name", "")),
                            "createdTime": str(f.get("createdTime", ""))})
        return listing

    def read_text(self, file_id):
        if file_id not in self._sizes:
            raise ReaderError("refused to read a file that was not in a listing")
        if self._sizes[file_id] > MAX_BYTES:
            raise ReaderError("file too large to be a packet")
        url = DRIVE_FILES + "/" + file_id + "?alt=media"
        status, data = self._http.request("GET", url, {"Authorization": "Bearer " + self._tokens.get()})
        if status != 200:
            raise _status_error(status, "reading a packet")
        if len(data) > MAX_BYTES:
            raise ReaderError("file too large to be a packet")
        try:
            return data.decode("utf-8-sig")  # a leading byte-order mark is dropped
        except UnicodeDecodeError:
            return ""  # treated as incomplete and re-checked next cycle

    def stop_present(self, root_folder_id):
        if root_folder_id != self.root_id:
            raise ReaderError("Bridge root ID requested by the poller does not match the configured ID")
        query = "'%s' in parents and name = 'STOP' and trashed = false" % self.root_id
        return len(self._list(query, "id", "checking STOP")) > 0


def build_reader(key_file, folder_id, root_id, http=None, sign_factory=google_auth_signer, environ=None):
    """Everything --live-api needs; raises ReaderError before any network use if the key is unsafe."""
    info = load_key_file(key_file, environ)
    sign = sign_factory(info)
    http = http or UrllibHttp()
    return ApiReader(folder_id, root_id, TokenSource(info, GuardedHttp(http), sign), http)
