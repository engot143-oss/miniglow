"""Candidate 3.1 regression tests: one group per finding of the independent review (R2G-028).

Fakes and loopback (127.0.0.1) only. No credentials, no real Google access.
"""
import contextlib
import http.client
import http.server
import io
import json
import ntpath
import os
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from unittest import mock

from bridge_poller import config, drive_api_reader as dar, packet_rules, poller
from bridge_poller.drive_reader import FakeDrive as PollFake
from bridge_poller.local_reader import LocalFolderReader, ReaderError
from bridge_poller.store import Store
from bridge_poller.tests.test_drive_api_reader import (FAKE_KEY, FOLDER, ROOT, FakeDrive, drive_file,
                                                       fake_sign, make_reader, packet)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "backlog_4.json")
FILE_ID = "abcdefghij0123456789"
AUTH = {"Authorization": "Bearer tok1"}


def setUpModule():
    patcher = mock.patch("time.sleep", lambda _seconds: None)
    patcher.start()
    unittest.addModuleCleanup(patcher.stop)


class Recorder:
    """Inner HTTP layer that records calls and returns a fixed reply."""

    def __init__(self, status=200, body=b"{}"):
        self.status, self.body, self.calls = status, body, []

    def request(self, method, url, headers, body=None):
        self.calls.append((method, url, headers, body))
        return self.status, self.body


# ---------------------------------------------------------------- finding 1: redirects

class _Target(http.server.BaseHTTPRequestHandler):
    seen = []

    def _hit(self):
        _Target.seen.append((self.command, self.path, self.headers.get("Authorization")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST = _hit

    def log_message(self, *args):
        pass


class _Redirector(http.server.BaseHTTPRequestHandler):
    location = ""
    code = 302

    def _redirect(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(_Redirector.code)
        self.send_header("Location", _Redirector.location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = _redirect

    def log_message(self, *args):
        pass


class RedirectTests(unittest.TestCase):
    def setUp(self):
        _Target.seen = []
        self.servers = []
        self.target = self._serve(_Target)
        self.redirector = self._serve(_Redirector)
        _Redirector.location = "http://127.0.0.1:%d/stolen" % self.target.server_port
        # Loopback only: make sure no proxy from the environment is used for these requests.
        with mock.patch.object(urllib.request, "getproxies", lambda: {}):
            self.http = dar.UrllibHttp()

    def _serve(self, handler):
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def url(self):
        return "http://127.0.0.1:%d/start" % self.redirector.server_port

    def test_redirect_is_not_followed_and_token_is_not_forwarded(self):
        for code in (301, 302, 303, 307, 308):
            _Redirector.code = code
            status, body = self.http.request("GET", self.url(), {"Authorization": "Bearer SECRET"})
            self.assertEqual((status, body), (code, b""))
        self.assertEqual(_Target.seen, [])  # the second server never received anything

    def test_token_post_redirect_is_not_followed(self):
        for code in (302, 303, 307):
            _Redirector.code = code
            status, _ = self.http.request("POST", self.url(), {"Content-Type": dar.TOKEN_CONTENT_TYPE}, b"a=b")
            self.assertEqual(status, code)
        self.assertEqual(_Target.seen, [])

    def test_guard_refuses_any_3xx_reply(self):
        for code in (300, 301, 302, 303, 304, 307, 308):
            guard = dar.GuardedHttp(Recorder(status=code))
            with self.assertRaises(ReaderError) as ctx:
                guard.request("GET", dar.DRIVE_FILES + "?q=x", AUTH)
            self.assertNotIn("tok1", str(ctx.exception))
            with self.assertRaises(ReaderError):
                guard.request("POST", dar.TOKEN_URI, {"Content-Type": dar.TOKEN_CONTENT_TYPE}, b"a=b")


# ---------------------------------------------------------------- finding 2: strict guard

class StrictGuardTests(unittest.TestCase):
    def test_allowed_requests(self):
        inner = Recorder()
        guard = dar.GuardedHttp(inner)
        listing = dar.DRIVE_FILES + "?" + urllib.parse.urlencode(
            {"q": "'%s' in parents" % FOLDER, "fields": "files(id)", "pageSize": "100", "spaces": "drive",
             "pageToken": "abc"})
        guard.request("GET", listing, AUTH)
        guard.request("GET", dar.DRIVE_FILES + "/" + FILE_ID + "?alt=media", AUTH)
        guard.request("POST", dar.TOKEN_URI, {"Content-Type": dar.TOKEN_CONTENT_TYPE}, b"a=b")
        self.assertEqual(len(inner.calls), 3)

    def test_tricky_urls_and_headers_are_refused(self):
        base = "https://www.googleapis.com/drive/v3/files"
        refused_gets = [
            base + "/../../v3/about?fields=*",
            base + "/%2e%2e/permissions",
            base + "/" + FILE_ID + "/permissions",
            base + "/" + FILE_ID + "/revisions",
            base + "/" + FILE_ID + "/../" + FILE_ID + "?alt=media",
            base + "?uploadType=media",
            base + "?q=x&q=y",
            base + "?q=x&supportsAllDrives=true",
            base,
            base + "/" + FILE_ID,
            base + "/" + FILE_ID + "?alt=media&fields=x",
            base + "/" + FILE_ID + "?alt=json",
            base + "/short?alt=media",
            "http://www.googleapis.com/drive/v3/files?q=x",
            "https://www.googleapis.com:8443/drive/v3/files?q=x",
            "https://user@www.googleapis.com/drive/v3/files?q=x",
            "https://www.googleapis.com.evil.example/drive/v3/files?q=x",
            "https://WWW.googleapis.com/drive/v3/files?q=x",
            base + "?q=x#frag",
            "https://www.googleapis.com/drive/v3/files/?q=x",
            "https://www.googleapis.com/upload/drive/v3/files?q=x",
        ]
        inner = Recorder()
        guard = dar.GuardedHttp(inner)
        for url in refused_gets:
            with self.assertRaises(ReaderError, msg=url):
                guard.request("GET", url, AUTH)
        good = base + "?q=x"
        for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Basic abc"},
                        dict(AUTH, **{"X-HTTP-Method-Override": "DELETE"}), dict(AUTH, **{"Content-Type": "x"})):
            with self.assertRaises(ReaderError, msg=headers):
                guard.request("GET", good, headers)
        with self.assertRaises(ReaderError):
            guard.request("GET", good, AUTH, b"")  # a GET may not carry a body, even an empty one
        for url, headers, body in [
            (dar.TOKEN_URI, {}, b"a=b"),
            (dar.TOKEN_URI, {"Content-Type": dar.TOKEN_CONTENT_TYPE, "X-HTTP-Method-Override": "DELETE"}, b"a"),
            (dar.TOKEN_URI + "?x=1", {"Content-Type": dar.TOKEN_CONTENT_TYPE}, b"a=b"),
            (dar.TOKEN_URI, {"Content-Type": dar.TOKEN_CONTENT_TYPE}, None),
            ("https://oauth2.googleapis.com/revoke", {"Content-Type": dar.TOKEN_CONTENT_TYPE}, b"a"),
        ]:
            with self.assertRaises(ReaderError, msg=url):
                guard.request("POST", url, headers, body)
        for method in ("PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "get"):
            with self.assertRaises(ReaderError):
                guard.request(method, good, AUTH)
        self.assertEqual(inner.calls, [])  # nothing refused ever reached the network layer


# ---------------------------------------------------------------- finding 3: malformed replies, interval

class MalformedReplyTests(unittest.TestCase):
    def reader_with_listing_reply(self, reply_bytes):
        drive = FakeDrive()
        reader = make_reader(drive)
        reader._tokens.get()
        drive.request = lambda m, u, h, b=None: (200, reply_bytes)
        return reader

    def test_non_object_replies_fail_closed(self):
        for body in (b"[]", b'"x"', b"5", b"null", b'{"files": ["x"]}', b'{"files": [null]}',
                     b'{"files": {}}', b'{"files": [], "nextPageToken": 5}'):
            with self.assertRaises(ReaderError, msg=body):
                self.reader_with_listing_reply(body).list_folder(FOLDER)
            with self.assertRaises(ReaderError, msg=body):
                self.reader_with_listing_reply(body).stop_present(ROOT)

    def test_bad_token_replies_fail_closed(self):
        for body in (b"[]", b'"x"', b"{}", b'{"access_token": 5}', b'{"access_token": "t", "expires_in": "x"}'):
            tokens = dar.TokenSource(FAKE_KEY, Recorder(body=body), fake_sign, now=lambda: 1000.0)
            with self.assertRaises(ReaderError, msg=body):
                tokens.get()

    def test_http_client_errors_become_reader_errors(self):
        for exc in (http.client.IncompleteRead(b""), http.client.RemoteDisconnected("x"),
                    http.client.BadStatusLine("x")):
            transport = dar.UrllibHttp()
            transport._opener = mock.Mock()
            transport._opener.open.side_effect = exc
            with self.assertRaises(ReaderError):
                transport.request("GET", dar.DRIVE_FILES + "?q=x", AUTH)

    def test_interval_below_60_is_refused_before_any_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "x.sqlite")
            for value in ("0", "59.9", "-5", "nan", "abc", "3601", "inf", "1e9"):
                with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit) as ctx:
                    poller.main(["--fixture", FIXTURE, "--db", db, "--interval", value])
                self.assertEqual(ctx.exception.code, 2)
                self.assertIn("--interval", err.getvalue())
            self.assertFalse(os.path.exists(db))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(poller.main(["--fixture", FIXTURE, "--db", db, "--max-checks", "1"]), 0)

    def test_unexpected_error_ends_as_clean_error_exit_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "x.sqlite")
            with mock.patch.object(PollFake, "list_folder", side_effect=TypeError("boom")):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    code = poller.main(["--fixture", FIXTURE, "--db", db, "--max-checks", "1"])
            self.assertEqual(code, 3)
            self.assertIn("ERROR: unexpected problem: TypeError", out.getvalue())
            store = Store(db)
            try:
                self.assertEqual(store.last_run()["end_reason"], "ERROR")
            finally:
                store.close()  # before the temporary folder is removed: Windows cannot delete an open file

    def test_malformed_listing_through_cli_is_exit_3(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = os.path.join(tmp, "k.json")
            with open(key, "w") as handle:
                json.dump(FAKE_KEY, handle)
            drive = FakeDrive()
            real_request = drive.request

            def request(method, url, headers, body=None):
                if url.startswith(dar.DRIVE_FILES + "?") and "STOP" not in urllib.parse.unquote_plus(url):
                    return 200, b"[]"
                return real_request(method, url, headers, body)

            drive.request = request
            real_build = dar.build_reader
            build = lambda k, f, r: real_build(k, f, r, http=drive, sign_factory=lambda info: fake_sign)
            env = {k: v for k, v in os.environ.items() if not k.startswith("BRIDGE_POLLER_")}
            env["LOCALAPPDATA"] = tmp
            db = os.path.join(tmp, "x.sqlite")
            with mock.patch.object(dar, "build_reader", build), mock.patch.dict(os.environ, env, clear=True):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    code = poller.main(["--live-api", "--key-file", key, "--db", db, "--max-checks", "1"])
            self.assertEqual(code, 3)
            self.assertIn("ERROR: Drive reply was not an object", out.getvalue())


# ---------------------------------------------------------------- findings 4 and 6: key location

class KeyLocationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = os.path.realpath(tmp.name)
        self.pkg = os.path.join(self.tmp, "pkg")

    def key_in(self, *parts):
        folder = os.path.join(self.tmp, *parts)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "k.json")
        with open(path, "w") as handle:
            json.dump(FAKE_KEY, handle)
        return path

    def load(self, path, environ=None, platform="posix"):
        return dar.load_key_file(path, environ=environ or {}, package_dir=self.pkg, platform=platform)

    def test_more_synced_folder_names_are_refused(self):
        for name in ("Shared drives", "GoogleDrive", "Google Drive Stream", "Other computers", "Meine Ablage",
                     "Mi unidad", "Box", "Box Sync", "box", "MY DRIVE"):
            with self.assertRaises(ReaderError, msg=name):
                self.load(self.key_in(name, "sub"))

    def test_similar_ordinary_names_are_allowed(self):
        for name in ("boxes", "toolbox", "drive-notes", "keys"):
            self.assertEqual(self.load(self.key_in(name))["type"], "service_account", name)

    def test_windows_requires_localappdata(self):
        local = os.path.join(self.tmp, "Local")
        inside = self.key_in("Local", "MiniGlow", "keys")
        outside = self.key_in("Elsewhere")
        self.assertTrue(self.load(inside, {"LOCALAPPDATA": local}, platform="nt"))
        for path, env in ((outside, {"LOCALAPPDATA": local}), (inside, {}), (inside, {"LOCALAPPDATA": " "})):
            with self.assertRaises(ReaderError):
                self.load(path, env, platform="nt")

    def test_network_paths_are_refused(self):
        for path in ("\\\\server\\share\\k.json", "//server/share/k.json", "\\\\?\\UNC\\server\\share\\k.json"):
            with self.assertRaises(ReaderError) as ctx:
                self.load(path)
            self.assertIn("network path", str(ctx.exception))
        with mock.patch.object(dar.os.path, "realpath", lambda p: "\\\\server\\share\\k.json"):
            with self.assertRaises(ReaderError):
                dar.check_key_location("k.json", environ={}, package_dir=self.pkg, platform="posix")

    def test_uncomparable_paths_fail_closed(self):
        path = self.key_in("keys")
        self.assertTrue(self.load(path))
        with mock.patch.object(dar.os.path, "commonpath", side_effect=ValueError("different drives")):
            with self.assertRaises(ReaderError):
                self.load(path)
        self.assertIsNone(_inside_with_value_error())

    def test_other_drive_letters_are_simply_not_inside(self):
        key = r"C:\Users\Eric\AppData\Local\MiniGlow\keys\k.json"
        self.assertIs(dar._inside(key, r"D:\code\bridge_poller", pathmod=ntpath), False)
        self.assertIs(dar._inside(key, r"d:\OneDrive", pathmod=ntpath), False)
        self.assertIs(dar._inside(key, r"c:\users\eric\appdata\local", pathmod=ntpath), True)
        self.assertIs(dar._inside(key, r"C:\code\bridge_poller", pathmod=ntpath), False)
        self.assertIsNone(dar._inside(key, r"\\server\share\x", pathmod=ntpath))  # cannot compare: unsafe


def _inside_with_value_error():
    with mock.patch.object(dar.os.path, "commonpath", side_effect=ValueError("x")):
        return dar._inside("a", "b")


# ---------------------------------------------------------------- finding 5: BOM and stuck packets

def poll_packet(pid, text):
    return {"id": "id-" + pid, "name": pid + "_RAY_to_GLOW_x.txt", "createdTime": "2026-10-05T00:00:00Z",
            "text": text}


def run_poll(fake, max_checks):
    store = Store()
    ticks = iter(range(1000, 5000))
    summary = poller.run(fake, store, max_checks=max_checks, interval=60, sleep=lambda s: None,
                         now=lambda: "t%d" % next(ticks))
    return store, summary


class BomAndStuckPacketTests(unittest.TestCase):
    def test_packet_rules_accept_a_leading_bom(self):
        text = "\ufeff" + packet("R2G-005")
        self.assertTrue(packet_rules.is_complete(text))
        self.assertEqual(packet_rules.header_packet_id(text), "R2G-005")
        self.assertTrue(packet_rules.is_complete(packet("R2G-005").replace("\n", "\r\n")))

    def test_api_reader_drops_a_bom(self):
        f = drive_file("R2G-001", text=packet("R2G-001"))
        f["_body"] = b"\xef\xbb\xbf" + f["_body"]
        f["size"] = str(len(f["_body"]))
        reader = make_reader(FakeDrive(files=[f]))
        reader.list_folder(FOLDER)
        self.assertTrue(reader.read_text(f["id"]).startswith("PACKET_ID: R2G-001"))

    def test_local_reader_drops_a_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "Bridge")
            folder = os.path.join(root, "Ray-to-Glow")
            os.makedirs(folder)
            with open(os.path.join(folder, "R2G-001_x.txt"), "wb") as handle:
                handle.write(b"\xef\xbb\xbf" + packet("R2G-001").encode())
            text = LocalFolderReader(folder, root).read_text("local:R2G-001_x.txt")
        self.assertTrue(packet_rules.is_complete(text))
        self.assertFalse(text.startswith("\ufeff"))

    def test_bom_packet_is_logged_as_new(self):
        fake = PollFake(files=[], schedule={2: [poll_packet("R2G-005", "\ufeff" + packet("R2G-005"))]})
        store, summary = run_poll(fake, 3)
        self.addCleanup(store.close)
        self.assertEqual(store.all_packets()[0]["state"], "NEW_LOGGED")
        self.assertEqual(summary["new_count"], 1)

    def test_stuck_incomplete_packet_escalates_once(self):
        stuck = poll_packet("R2G-005", packet("R2G-005", end=False))
        fake = PollFake(files=[], schedule={1: [stuck]}, text_updates={6: {"id-R2G-005": packet("R2G-005")}})
        store, summary = run_poll(fake, 8)
        self.addCleanup(store.close)
        rows = store.all_packets()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["state"], rows[0]["check_number"]), ("NEEDS_ERIC", poller.INCOMPLETE_LIMIT))
        self.assertEqual(summary["new_count"], 0)  # completing later does not clear the flag
        self.assertEqual(fake.calls.count("read_text"), poller.INCOMPLETE_LIMIT)  # not re-read after the flag

    def test_incomplete_streak_shorter_than_limit_is_not_escalated(self):
        partial = poll_packet("R2G-005", packet("R2G-005", end=False))
        updates = {poller.INCOMPLETE_LIMIT: {"id-R2G-005": packet("R2G-005")}}
        fake = PollFake(files=[], schedule={1: [partial]}, text_updates=updates)
        store, summary = run_poll(fake, 5)
        self.addCleanup(store.close)
        row = store.all_packets()[0]
        self.assertEqual((row["state"], row["check_number"]), ("NEW_LOGGED", poller.INCOMPLETE_LIMIT))

    def test_streak_carries_over_to_the_next_run(self):
        stuck = poll_packet("R2G-005", packet("R2G-005", end=False))
        store = Store()
        self.addCleanup(store.close)
        for run_number in range(1, 4):  # short runs: one check each
            fake = PollFake(files=[], schedule={1: [stuck]}) if run_number == 1 else PollFake(files=[stuck])
            poller.run(fake, store, max_checks=1, interval=60, sleep=lambda s: None, now=lambda: "t")
            if run_number == 1:
                self.assertEqual(store.incomplete_streaks(), {"id-R2G-005": 1})
                self.assertEqual(store.all_packets(), [])
        rows = store.all_packets()
        self.assertEqual((rows[0]["packet_id"], rows[0]["state"]), ("R2G-005", "NEEDS_ERIC"))  # never BACKLOG

    def test_packet_completed_between_runs_is_logged_new_at_startup(self):
        partial = poll_packet("R2G-005", packet("R2G-005", end=False))
        store = Store()
        self.addCleanup(store.close)
        poller.run(PollFake(files=[], schedule={1: [partial]}), store, max_checks=1, interval=60,
                   sleep=lambda s: None, now=lambda: "t")
        done = poll_packet("R2G-005", packet("R2G-005"))
        summary = poller.run(PollFake(files=[done]), store, max_checks=1, interval=60,
                             sleep=lambda s: None, now=lambda: "t")
        row = store.all_packets()[0]
        self.assertEqual((row["state"], row["check_number"], summary["new_count"]), ("NEW_LOGGED", 0, 1))
        self.assertEqual(store.incomplete_streaks(), {})

    def test_untouched_backlog_is_still_not_read_at_startup(self):
        fake = PollFake(files=[poll_packet("R2G-001", packet("R2G-001", end=False))])
        store, _ = run_poll(fake, 0)
        self.addCleanup(store.close)
        self.assertEqual(store.all_packets()[0]["state"], "BACKLOG")
        self.assertNotIn("read_text", fake.calls)

    def test_renamed_file_starts_a_fresh_streak(self):
        store = Store()
        self.addCleanup(store.close)
        self.assertEqual([store.bump_incomplete("f1", "R2G-005") for _ in range(2)], [1, 2])
        self.assertEqual(store.bump_incomplete("f1", "R2G-006"), 1)
        self.assertEqual(store.bump_incomplete("f1", "R2G-006"), 2)

    def test_empty_listing_keeps_streaks_even_with_an_empty_database(self):
        partial = poll_packet("R2G-005", packet("R2G-005", end=False))
        fake = PollFake(files=[], schedule={1: [partial]}, remove={2: ["id-R2G-005"]})
        store, _ = run_poll(fake, 2)
        self.addCleanup(store.close)
        self.assertEqual(store.incomplete_streaks(), {"id-R2G-005": 1})

    def test_streak_restarts_when_the_file_disappears(self):
        partial = poll_packet("R2G-005", packet("R2G-005", end=False))
        other = poll_packet("R2G-001", packet("R2G-001"))
        fake = PollFake(files=[other], schedule={1: [partial], 4: [partial]}, remove={3: ["id-R2G-005"]})
        store, _ = run_poll(fake, 5)
        self.addCleanup(store.close)
        self.assertEqual({r["packet_id"] for r in store.all_packets()}, {"R2G-001"})  # 2 + 2 checks, never 3


# ---------------------------------------------------------------- finding 7: parents and expires_in

class ReplyFieldTests(unittest.TestCase):
    def test_parents_must_be_a_list(self):
        good = drive_file("R2G-001")
        as_string = drive_file("R2G-002", parents="zz" + FOLDER)
        missing = drive_file("R2G-003")
        del missing["parents"]
        reader = make_reader(FakeDrive(files=[good, as_string, missing]))
        self.assertEqual([f["id"] for f in reader.list_folder(FOLDER)], [good["id"]])
        self.assertEqual(reader.ignored, 2)

    def test_listing_query_asks_only_for_text_files(self):
        drive = FakeDrive(files=[drive_file("R2G-001")])
        captured = []
        real = drive.request
        drive.request = lambda m, u, h, b=None: (captured.append(u), real(m, u, h, b))[1]
        make_reader(drive).list_folder(FOLDER)
        query = dict(urllib.parse.parse_qsl(captured[-1].split("?", 1)[1]))["q"]
        self.assertIn("mimeType = 'text/plain'", query)

    def test_expires_in_is_clamped_and_must_be_a_sensible_whole_number(self):
        reply = lambda lifetime: json.dumps({"access_token": "t", "expires_in": lifetime}).encode()
        tokens = dar.TokenSource(FAKE_KEY, Recorder(body=reply(99999999999)), fake_sign, now=lambda: 1000.0)
        tokens.get()
        self.assertEqual(tokens.expires, 1000 + dar.MAX_TOKEN_SECONDS)
        for body in (reply(0), reply(-5), reply(119), reply(True), reply("3600"), reply(3600.5),
                     b'{"access_token": "t", "expires_in": Infinity}'):
            tokens = dar.TokenSource(FAKE_KEY, Recorder(body=body), fake_sign, now=lambda: 1000.0)
            with self.assertRaises(ReaderError, msg=body):
                tokens.get()

    def test_token_must_be_plain_printable_text(self):
        for token in ("t\r\nX: y", "t t", "", "t" * 5000, "t\u00e9"):
            body = json.dumps({"access_token": token, "expires_in": 3600}).encode()
            tokens = dar.TokenSource(FAKE_KEY, Recorder(body=body), fake_sign, now=lambda: 1000.0)
            with self.assertRaises(ReaderError) as ctx:
                tokens.get()
            self.assertNotIn("X: y", str(ctx.exception))


class HiddenCharacterTests(unittest.TestCase):
    def test_ids_with_a_trailing_line_break_are_refused(self):
        for value in ("abcdefghij\n", "abcdefghij\r", " abcdefghij"):
            with self.assertRaises(ReaderError):
                dar._check_id(value, "x")

    def test_urls_and_headers_with_hidden_characters_are_refused(self):
        inner = Recorder()
        guard = dar.GuardedHttp(inner)
        for url in (dar.DRIVE_FILES + "/abcdefghij\n?alt=media", "https://www.goo\tgleapis.com/drive/v3/files?q=x",
                    " " + dar.DRIVE_FILES + "?q=x", dar.DRIVE_FILES + "?q=a b"):
            with self.assertRaises(ReaderError, msg=url):
                guard.request("GET", url, AUTH)
        for auth in ("Bearer t\r\nX: y", "Bearer t t", "Bearer \u00e9"):
            with self.assertRaises(ReaderError):
                guard.request("GET", dar.DRIVE_FILES + "?q=x", {"Authorization": auth})
        self.assertEqual(inner.calls, [])


if __name__ == "__main__":
    unittest.main()
