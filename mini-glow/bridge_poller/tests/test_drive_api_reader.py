"""Phase 3 tests: read-only Drive API reader with a FAKE network. No credentials, no real Google access."""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
import urllib.parse
from unittest import mock

from bridge_poller import config, drive_api_reader as dar, poller
from bridge_poller.local_reader import ReaderError
from bridge_poller.store import Store

FOLDER = "1CIQ4F-nXR_N6SOr_rPB4qm0HTwqrINEA"
ROOT = "1shjWGaRUvoahNb72hkI2Hez0qn7Kzj_i"
FAKE_KEY = {"type": "service_account", "client_email": "reader@example-project.iam.gserviceaccount.com",
            "private_key": "not-a-real-key", "private_key_id": "kid123", "token_uri": dar.TOKEN_URI}


def packet(pid, end=True):
    text = "PACKET_ID: %s\nFROM: RAY\nTO: GLOW\nREPLY_TO: G2R-001\nSTATUS: RESPONSE\n\nMESSAGE:\nhello\n" % pid
    return text + ("END_OF_PACKET\n" if end else "")


def drive_file(pid, fid=None, mime="text/plain", parents=None, text=None, size=None):
    fid = fid or ("file%s" % pid.replace("-", "")).ljust(20, "x")
    body = (text if text is not None else packet(pid)).encode("utf-8")
    return {"id": fid, "name": "%s_RAY_to_GLOW_x.txt" % pid, "mimeType": mime,
            "createdTime": "2026-10-05T00:00:00.000Z", "size": str(size if size is not None else len(body)),
            "parents": parents if parents is not None else [FOLDER], "_body": body}


def setUpModule():
    # Command-line runs now need --interval 60 or more; tests never really wait.
    patcher = mock.patch("time.sleep", lambda _seconds: None)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


class FakeDrive:
    """Fake Google endpoints. Records every request; never touches the network."""

    def __init__(self, files=None, stop=False):
        self.files = list(files or [])
        self.stop = stop
        self.calls = []
        self.fail = {}  # kind -> HTTP status to return ("token", "list", "stop", "read")
        self.page_size = 100
        self.token_count = 0

    def request(self, method, url, headers, body=None):
        self.calls.append((method, url.split("?")[0], headers, body))
        if url == dar.TOKEN_URI:
            if "token" in self.fail:
                return self.fail["token"], b"{}"
            self.token_count += 1
            return 200, json.dumps({"access_token": "tok%d" % self.token_count, "expires_in": 3600}).encode()
        if headers.get("Authorization", "").split(" ")[-1].startswith("tok") is False:
            return 401, b""
        if url.startswith(dar.DRIVE_FILES + "?"):
            params = dict(urllib.parse.parse_qsl(url.split("?", 1)[1]))
            if "name = 'STOP'" in params["q"]:
                if "stop" in self.fail:
                    return self.fail["stop"], b""
                return 200, json.dumps({"files": [{"id": "stopfile0000000"}] if self.stop else []}).encode()
            if "list" in self.fail:
                return self.fail["list"], b""
            start = int(params.get("pageToken", "0"))
            chunk = self.files[start:start + self.page_size]
            reply = {"files": [{k: v for k, v in f.items() if k != "_body"} for f in chunk]}
            if start + self.page_size < len(self.files):
                reply["nextPageToken"] = str(start + self.page_size)
            return 200, json.dumps(reply).encode()
        if url.startswith(dar.DRIVE_FILES + "/"):
            if "read" in self.fail:
                return self.fail["read"], b""
            fid = url[len(dar.DRIVE_FILES) + 1:].split("?")[0]
            for f in self.files:
                if f["id"] == fid:
                    return 200, f["_body"]
            return 404, b""
        return 400, b""


def fake_sign(data):
    return b"signature-for-tests"


def make_reader(drive, clock=None):
    tokens = dar.TokenSource(FAKE_KEY, dar.GuardedHttp(drive), fake_sign, now=clock or (lambda: 1000.0))
    return dar.ApiReader(FOLDER, ROOT, tokens, drive)


def run_api(drive, store, max_checks=3, on_sleep=None):
    reader = make_reader(drive)
    calls = {"n": 0}

    def sleep(_seconds):
        calls["n"] += 1
        if on_sleep:
            on_sleep(calls["n"])

    return poller.run(reader, store, folder_id=FOLDER, root_id=ROOT, max_checks=max_checks,
                      interval=60, sleep=sleep, now=lambda: "t")


class KeyFileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.safe = os.path.join(self.tmp, "secrets")
        os.makedirs(self.safe)

    def write(self, name, content, folder=None):
        path = os.path.join(folder or self.safe, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content if isinstance(content, str) else json.dumps(content))
        return path

    def load(self, path, environ=None):
        return dar.load_key_file(path, environ=environ or {}, package_dir=os.path.join(self.tmp, "pkg"), platform="posix")

    def test_good_key_loads(self):
        self.assertEqual(self.load(self.write("k.json", FAKE_KEY))["client_email"], FAKE_KEY["client_email"])

    def test_missing_or_unconfigured_key_fails(self):
        for path in (None, "", os.path.join(self.safe, "nope.json")):
            with self.assertRaises(ReaderError):
                self.load(path)

    def test_bad_key_contents_fail(self):
        bad = [
            "not json",
            [1, 2],
            dict(FAKE_KEY, type="authorized_user"),
            {k: v for k, v in FAKE_KEY.items() if k != "private_key"},
            dict(FAKE_KEY, client_email=""),
            dict(FAKE_KEY, token_uri="https://evil.example/token"),
        ]
        for i, content in enumerate(bad):
            with self.assertRaises(ReaderError):
                self.load(self.write("bad%d.json" % i, content))

    def test_oversized_key_fails(self):
        with self.assertRaises(ReaderError):
            self.load(self.write("big.json", dict(FAKE_KEY, pad="x" * (dar.MAX_KEY_BYTES + 1))))

    def test_key_inside_repository_is_refused(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, ".git"))
        pkg = os.path.join(repo, "mini-glow", "bridge_poller")
        os.makedirs(pkg)
        path = self.write("k.json", FAKE_KEY, folder=os.path.join(repo, "mini-glow"))
        with self.assertRaises(ReaderError):
            dar.load_key_file(path, environ={}, package_dir=pkg, platform="posix")
        outside = self.write("k2.json", FAKE_KEY)
        self.assertTrue(dar.load_key_file(outside, environ={}, package_dir=pkg, platform="posix"))

    def test_key_inside_package_is_refused(self):
        pkg = os.path.join(self.tmp, "pkg")
        path = self.write("k.json", FAKE_KEY, folder=pkg)
        with self.assertRaises(ReaderError):
            dar.load_key_file(path, environ={}, package_dir=pkg, platform="posix")

    def test_key_inside_synced_folders_is_refused(self):
        onedrive = os.path.join(self.tmp, "SomeSync")
        path = self.write("k.json", FAKE_KEY, folder=onedrive)
        with self.assertRaises(ReaderError):
            self.load(path, environ={"OneDrive": onedrive})
        for name in ("My Drive", "Google Drive", "OneDrive - Work", "Dropbox", "iCloudDrive"):
            with self.assertRaises(ReaderError):
                self.load(self.write("k.json", FAKE_KEY, folder=os.path.join(self.tmp, name, "sub")))

    def test_signer_needs_google_auth(self):
        with mock.patch.dict("sys.modules", {"google": None, "google.auth": None}):
            with self.assertRaises(ReaderError):
                dar.google_auth_signer(FAKE_KEY)


class GuardTests(unittest.TestCase):
    def test_only_drive_get_and_token_post_are_allowed(self):
        drive = FakeDrive()
        guard = dar.GuardedHttp(drive)
        refused = [
            ("POST", dar.DRIVE_FILES, b"{}"),
            ("POST", "https://www.googleapis.com/upload/drive/v3/files", b"x"),
            ("PATCH", dar.DRIVE_FILES + "/abc", b"{}"),
            ("PUT", dar.DRIVE_FILES + "/abc", b"{}"),
            ("DELETE", dar.DRIVE_FILES + "/abc", None),
            ("GET", "https://example.com/files?x=1", None),
            ("GET", "https://www.googleapis.com/drive/v3/permissions?x=1", None),
            ("GET", dar.DRIVE_FILES + "?q=x", b"body"),
            ("POST", "https://oauth2.googleapis.com/revoke", b"x"),
        ]
        for method, url, body in refused:
            with self.assertRaises(ReaderError):
                guard.request(method, url, {}, body)
        self.assertEqual(drive.calls, [])  # nothing refused ever reached the network layer
        self.assertEqual(guard.request("POST", dar.TOKEN_URI, {"Content-Type": dar.TOKEN_CONTENT_TYPE}, b"a=b")[0], 200)

    def test_source_has_one_post_and_no_write_methods(self):
        with open(dar.__file__, encoding="ascii") as handle:
            source = handle.read()
        self.assertEqual(source.count('"POST"'), 2)  # one allowed in the guard, one used for the token
        for forbidden in ('"PUT"', '"PATCH"', '"DELETE"', "upload", "batchUpdate", "permissions", "copy"):
            self.assertNotIn(forbidden, source, forbidden)
        public = {m for m in dir(dar.ApiReader) if not m.startswith("_")}
        self.assertEqual(public, {"list_folder", "read_text", "stop_present"})

    def test_every_request_from_a_run_is_a_drive_get_or_the_token_post(self):
        drive = FakeDrive(files=[drive_file("R2G-001")])
        run_api(drive, self._store(), 3, on_sleep=lambda n: n == 2 and drive.files.append(drive_file("R2G-002")))
        for method, url, _headers, _body in drive.calls:
            self.assertTrue((method == "GET" and url.startswith(dar.DRIVE_FILES)) or
                            (method == "POST" and url == dar.TOKEN_URI), (method, url))
        self.assertEqual(sum(1 for c in drive.calls if c[0] == "POST"), 1)  # token fetched once and cached

    def _store(self):
        store = Store()
        self.addCleanup(store.close)
        return store


class TokenTests(unittest.TestCase):
    def test_token_request_is_a_signed_jwt_for_read_only_scope(self):
        drive = FakeDrive()
        tokens = dar.TokenSource(FAKE_KEY, dar.GuardedHttp(drive), fake_sign, now=lambda: 1000.0)
        self.assertEqual(tokens.get(), "tok1")
        method, url, headers, body = drive.calls[0]
        self.assertEqual((method, url), ("POST", dar.TOKEN_URI))
        form = dict(urllib.parse.parse_qsl(body.decode()))
        self.assertEqual(form["grant_type"], "urn:ietf:params:oauth:grant-type:jwt-bearer")
        head, claims, sig = form["assertion"].split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pad(claims)))
        self.assertEqual(claims["scope"], "https://www.googleapis.com/auth/drive.readonly")
        self.assertEqual(claims["aud"], dar.TOKEN_URI)
        self.assertEqual(claims["iss"], FAKE_KEY["client_email"])
        self.assertEqual(json.loads(base64.urlsafe_b64decode(pad(head)))["alg"], "RS256")
        self.assertEqual(base64.urlsafe_b64decode(pad(sig)), b"signature-for-tests")

    def test_token_is_cached_then_renewed_near_expiry(self):
        drive, clock = FakeDrive(), {"t": 1000.0}
        tokens = dar.TokenSource(FAKE_KEY, dar.GuardedHttp(drive), fake_sign, now=lambda: clock["t"])
        self.assertEqual(tokens.get(), "tok1")
        clock["t"] += 3000
        self.assertEqual(tokens.get(), "tok1")
        clock["t"] += 600  # within 60 s of expiry
        self.assertEqual(tokens.get(), "tok2")

    def test_token_failures_fail_closed(self):
        for status in (400, 401, 403, 500):
            drive = FakeDrive()
            drive.fail["token"] = status
            with self.assertRaises(ReaderError):
                dar.TokenSource(FAKE_KEY, dar.GuardedHttp(drive), fake_sign).get()
        bad_reply = FakeDrive()
        bad_reply.request = lambda m, u, h, b=None: (200, b"not json")
        with self.assertRaises(ReaderError):
            dar.TokenSource(FAKE_KEY, dar.GuardedHttp(bad_reply), fake_sign).get()


class ReaderTests(unittest.TestCase):
    def test_listing_filters_type_and_parent(self):
        drive = FakeDrive(files=[
            drive_file("R2G-001"),
            drive_file("R2G-002", mime="application/vnd.google-apps.document"),
            drive_file("R2G-003", parents=["someOtherFolderId0001"]),
            dict(drive_file("R2G-004"), id="bad id!"),
        ])
        reader = make_reader(drive)
        listing = reader.list_folder(FOLDER)
        self.assertEqual([f["name"] for f in listing], ["R2G-001_RAY_to_GLOW_x.txt"])
        self.assertEqual(reader.ignored, 3)

    def test_listing_follows_all_pages(self):
        drive = FakeDrive(files=[drive_file("R2G-%03d" % i) for i in range(1, 8)])
        drive.page_size = 3
        self.assertEqual(len(make_reader(drive).list_folder(FOLDER)), 7)

    def test_endless_pages_are_treated_as_incomplete(self):
        drive = FakeDrive(files=[drive_file("R2G-%03d" % i) for i in range(1, 40)])
        drive.page_size = 1
        with self.assertRaises(ReaderError):
            make_reader(drive).list_folder(FOLDER)

    def test_read_only_files_from_a_listing_and_within_size(self):
        big = drive_file("R2G-002", size=dar.MAX_BYTES + 1)
        drive = FakeDrive(files=[drive_file("R2G-001"), big])
        reader = make_reader(drive)
        with self.assertRaises(ReaderError):
            reader.read_text(drive.files[0]["id"])  # not listed yet
        reader.list_folder(FOLDER)
        self.assertTrue(reader.read_text(drive.files[0]["id"]).endswith("END_OF_PACKET\n"))
        with self.assertRaises(ReaderError):
            reader.read_text(big["id"])

    def test_body_over_cap_or_undecodable(self):
        drive = FakeDrive(files=[drive_file("R2G-001", size=10)])
        reader = make_reader(drive)
        reader.list_folder(FOLDER)
        drive.files[0]["_body"] = b"x" * (dar.MAX_BYTES + 1)
        with self.assertRaises(ReaderError):
            reader.read_text(drive.files[0]["id"])
        drive.files[0]["_body"] = b"PACKET_ID: R2G-001\n\xff\xfe"
        self.assertEqual(reader.read_text(drive.files[0]["id"]), "")

    def test_stop_and_mismatched_ids(self):
        reader = make_reader(FakeDrive(stop=True))
        self.assertTrue(reader.stop_present(ROOT))
        self.assertFalse(make_reader(FakeDrive()).stop_present(ROOT))
        with self.assertRaises(ReaderError):
            reader.stop_present(FOLDER)
        with self.assertRaises(ReaderError):
            reader.list_folder(ROOT)

    def test_invalid_configured_ids_are_refused(self):
        tokens = dar.TokenSource(FAKE_KEY, dar.GuardedHttp(FakeDrive()), fake_sign)
        for folder, root in (("x' or '1'='1", ROOT), (FOLDER, "short"), (FOLDER, FOLDER)):
            with self.assertRaises(ReaderError):
                dar.ApiReader(folder, root, tokens, FakeDrive())

    def test_http_errors_fail_closed(self):
        for kind in ("list", "stop", "read"):
            for status in (401, 403, 404, 429, 500, 503):
                drive = FakeDrive(files=[drive_file("R2G-001")])
                reader = make_reader(drive)
                if kind == "read":
                    reader.list_folder(FOLDER)
                drive.fail[kind] = status
                with self.assertRaises(ReaderError):
                    {"list": lambda: reader.list_folder(FOLDER), "stop": lambda: reader.stop_present(ROOT),
                     "read": lambda: reader.read_text(drive.files[0]["id"])}[kind]()

    def test_network_failure_and_bad_reply_fail_closed(self):
        class Down:
            def request(self, *a, **k):
                raise ReaderError("network problem: URLError")

        with self.assertRaises(ReaderError):
            make_reader(Down()).stop_present(ROOT)
        drive = FakeDrive()
        reader = make_reader(drive)
        reader._tokens.get()
        drive.request = lambda m, u, h, b=None: (200, b"<html>")
        with self.assertRaises(ReaderError):
            reader.list_folder(FOLDER)


class PollerWithApiTests(unittest.TestCase):
    def new_store(self):
        store = Store()
        self.addCleanup(store.close)
        return store

    def test_baseline_then_new_packet_logged_once(self):
        drive = FakeDrive(files=[drive_file("R2G-001")])
        store = self.new_store()
        summary = run_api(drive, store, 4, on_sleep=lambda n: n == 2 and drive.files.append(drive_file("R2G-002")))
        rows = {r["packet_id"]: r for r in store.all_packets()}
        self.assertEqual(rows["R2G-001"]["state"], "BACKLOG")
        self.assertEqual((rows["R2G-002"]["state"], rows["R2G-002"]["check_number"]), ("NEW_LOGGED", 2))
        self.assertEqual(summary["new_count"], 1)
        summary2 = run_api(drive, store, 2)
        self.assertEqual(summary2["new_count"], 0)

    def test_stop_mid_run(self):
        drive = FakeDrive(files=[drive_file("R2G-001")])
        summary = run_api(drive, self.new_store(), 5, on_sleep=lambda n: n == 3 and setattr(drive, "stop", True))
        self.assertEqual((summary["end_reason"], summary["checks_done"]), ("STOP", 2))

    def test_access_lost_mid_run_ends_as_error_with_rows_unchanged(self):
        drive = FakeDrive(files=[drive_file("R2G-001")])
        store = self.new_store()

        def revoke(n):
            if n == 2:
                drive.fail["list"] = 403

        with self.assertRaises(ReaderError):
            run_api(drive, store, 4, on_sleep=revoke)
        self.assertEqual(store.last_run()["end_reason"], "ERROR")
        self.assertEqual(store.all_packets()[0]["state"], "BACKLOG")

    def test_empty_listing_uses_suspect_rule(self):
        drive = FakeDrive(files=[drive_file("R2G-001")])
        store = self.new_store()
        summary = run_api(drive, store, 3, on_sleep=lambda n: n == 1 and drive.files.clear())
        self.assertEqual(summary["health"], "NEEDS_ERIC")
        self.assertEqual(store.all_packets()[0]["state"], "BACKLOG")

    def test_request_count_for_a_full_run(self):
        drive = FakeDrive(files=[drive_file("R2G-001")])
        run_api(drive, self.new_store(), 10)
        self.assertEqual(len(drive.calls), 1 + 11 + 11)  # token + STOP checks + listings


class ApiCliTests(unittest.TestCase):
    def main(self, argv, env=None):
        out = io.StringIO()
        clean = {k: v for k, v in os.environ.items() if not k.startswith("BRIDGE_POLLER_")}
        clean["LOCALAPPDATA"] = self.tmp  # on Windows a key must sit under %LOCALAPPDATA%
        clean.update(env or {})
        with mock.patch.dict(os.environ, clean, clear=True), contextlib.redirect_stdout(out):
            code = poller.main(argv)
        return code, out.getvalue()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def test_no_key_stays_blocked_without_database(self):
        db = os.path.join(self.tmp, "x.sqlite")
        code, out = self.main(["--live-api", "--db", db])
        self.assertEqual(code, 2)
        self.assertIn("BLOCKED", out)
        self.assertFalse(os.path.exists(db))

    def test_bad_key_fails_before_network_and_database(self):
        key = os.path.join(self.tmp, "k.json")
        with open(key, "w") as handle:
            handle.write("{}")
        db = os.path.join(self.tmp, "x.sqlite")
        with mock.patch.object(dar.UrllibHttp, "request", side_effect=AssertionError("network used")):
            code, out = self.main(["--live-api", "--key-file", key, "--db", db])
        self.assertEqual(code, 3)
        self.assertIn("ERROR", out)
        self.assertFalse(os.path.exists(db))

    def test_missing_google_auth_fails_closed(self):
        key = os.path.join(self.tmp, "k.json")
        with open(key, "w") as handle:
            json.dump(FAKE_KEY, handle)
        db = os.path.join(self.tmp, "x.sqlite")
        with mock.patch.dict("sys.modules", {"google": None, "google.auth": None}):
            code, out = self.main(["--live-api", "--db", db], env={config.ENV_KEY_FILE: key})
        self.assertEqual(code, 3)
        self.assertIn("google-auth", out)
        self.assertFalse(os.path.exists(db))

    def test_full_cli_run_with_fake_network(self):
        key = os.path.join(self.tmp, "k.json")
        with open(key, "w") as handle:
            json.dump(FAKE_KEY, handle)
        drive = FakeDrive(files=[drive_file("R2G-001")])
        db = os.path.join(self.tmp, "x.sqlite")
        real_build = dar.build_reader
        build = lambda k, f, r: real_build(k, f, r, http=drive, sign_factory=lambda info: fake_sign)
        with mock.patch.object(dar, "build_reader", build):
            code, out = self.main(["--live-api", "--key-file", key, "--db", db, "--max-checks", "2", "--interval", "60"])
        self.assertEqual(code, 0)
        self.assertIn("end_reason=WINDOW_DONE checks_done=2 new_count=0 suspect_listings=0 health=OK", out)

    def test_two_modes_at_once_are_refused(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                poller.main(["--live", "--live-api"])

    def test_key_file_setting_has_no_default(self):
        self.assertIsNone(config.resolve_key_file(environ={}))
        self.assertEqual(config.resolve_key_file(environ={config.ENV_KEY_FILE: "k"}), "k")


if __name__ == "__main__":
    unittest.main()
