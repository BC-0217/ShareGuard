"""Tests for the GUI scan session: IPC schema, cancellation and cleanup.

These tests use real spawned processes with small fake worker functions
(defined at module level so the spawned child can import them).  They prove
the session protocol and process handling, not the scanner itself and not
the visible GUI.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from shareguard import gui_session as gs  # noqa: E402


# ---------------------------------------------------------------------------
# Fake worker targets (run in the spawned child).


def _send(conn, message):
    conn.send_bytes(gs.encode_message(message))


def worker_result(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    _send(result_conn, {"type": "progress", "gen": gen, "counts": {"targets": 2}})
    if location_conn is not None:
        location_conn.send_bytes(gs.encode_location(gen, "T1", paths[0], None))
        location_conn.send_bytes(gs.encode_location(gen, "T2", paths[0], "inner/a.txt"))
    _send(result_conn, {"type": "result", "gen": gen, "result": {"echo": len(paths)}})


def worker_cooperative(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    deadline = time.monotonic() + 30
    while not cancel_event.is_set() and time.monotonic() < deadline:
        time.sleep(0.02)
    _send(result_conn, {"type": "result", "gen": gen, "result": {"completeness": "cancelled"}})


def worker_ignore_cancel(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    time.sleep(60)


def worker_die(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    os._exit(7)


def worker_garbage(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    result_conn.send_bytes(b"{not json")
    time.sleep(5)


def worker_wrong_generation(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    _send(result_conn, {"type": "result", "gen": gen + 1, "result": {}})
    time.sleep(5)


def worker_extra_key(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    _send(result_conn, {"type": "progress", "gen": gen, "counts": {"targets": 1}, "path": "x"})
    time.sleep(5)


def worker_partial_then_die(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    payload = gs.encode_message({"type": "result", "gen": gen, "result": {"blob": "x" * (12 * 1024 * 1024)}})
    sender = threading.Thread(target=result_conn.send_bytes, args=(payload,), daemon=True)
    sender.start()
    time.sleep(0.02)
    os._exit(9)


def worker_large_result(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    _send(result_conn, {"type": "result", "gen": gen, "result": {"blob": "y" * (8 * 1024 * 1024)}})


def worker_complete_result(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    _send(result_conn, {"type": "result", "gen": gen, "result": {"completeness": "complete"}})


def worker_oversized(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    try:
        result_conn.send_bytes(b" " * (gs.MAX_RESULT_BYTES + 10))
    except (BrokenPipeError, OSError):
        pass
    time.sleep(5)


def worker_location_flood(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    for index in range(gs.MAX_LOCATIONS + 500):
        location_conn.send_bytes(gs.encode_location(gen, "T%d" % index, "C:/synthetic/%d.txt" % index, None))
    # Malformed and foreign-generation entries must be ignored.
    location_conn.send_bytes(b"[1,2]")
    location_conn.send_bytes(gs.encode_location(gen + 1, "OTHER", "C:/other.txt", None))
    _send(result_conn, {"type": "result", "gen": gen, "result": {}})


def worker_hang_location_pipe(gen, paths, policy, cancel_event, result_conn, location_conn, scope_conn):
    # Keeps writing locations; the parent stops draining after close().
    index = 0
    while True:
        location_conn.send_bytes(gs.encode_location(gen, "H%d" % (index % 1000), "C:/" + "p" * 2000, None))
        index += 1


# ---------------------------------------------------------------------------


def passthrough(raw):
    return gs.ValidatedResult(None, raw, 0)


def run_until_finished(session, limit=20.0):
    deadline = time.monotonic() + limit
    events = []
    while not session.finished and time.monotonic() < deadline:
        progress = session.poll()
        if progress:
            events.append(progress)
        time.sleep(0.02)
    return events


def final_data(session):
    return session.final["result"].data


class ProtocolTests(unittest.TestCase):
    def test_progress_sanitized_to_allowlist(self):
        counts = gs.sanitize_progress(
            {"entries": 3, "path": "C:/secret", "current_target": "T4", "bytes": True, "issues": -1, "targets": 2}
        )
        self.assertEqual(counts, {"entries": 3, "targets": 2})
        self.assertEqual(gs.sanitize_progress("C:/x"), {})

    def test_parse_accepts_exact_shapes(self):
        ok = gs.parse_message(gs.encode_message({"type": "error", "gen": 4, "code": "timeout"}), 4)
        self.assertEqual(ok["code"], "timeout")
        ok = gs.parse_message(gs.encode_message({"type": "result", "gen": 4, "result": {"a": [1, None]}}), 4)
        self.assertEqual(ok["result"], {"a": [1, None]})

    def test_parse_rejects_violations(self):
        bad = [
            b"\xff\xfe",
            b"[]",
            b'{"type":"error","gen":4,"code":"C:\\\\Users\\\\x"}',
            b'{"type":"error","gen":5,"code":"timeout"}',
            b'{"type":"error","gen":true,"code":"timeout"}',
            b'{"type":"progress","gen":4,"counts":{"path":1}}',
            b'{"type":"progress","gen":4,"counts":{"targets":-1}}',
            b'{"type":"progress","gen":4,"counts":{"current_target":"T1"}}',
            b'{"type":"progress","gen":4,"counts":{},"extra":1}',
            b'{"type":"result","gen":4,"result":[]}',
            b'{"type":"result","gen":4,"result":{"x":NaN}}',
            b'{"type":"location","gen":4}',
            b'{"type":"result","gen":4,"result":{}}' + b" " * gs.MAX_RESULT_BYTES,
        ]
        for data in bad:
            with self.subTest(data=data[:40]):
                with self.assertRaises(gs.ProtocolError):
                    gs.parse_message(data, 4)

    def test_location_encoding_bounds(self):
        self.assertIsNone(gs.encode_location(1, "T", "x" * (gs.MAX_PATH_CHARS + 1), None))
        self.assertIsNone(gs.encode_location(1, "T" * 200, "C:/a", None))
        self.assertIsNone(gs.encode_location(1, "T", "C:/a", 5))
        data = gs.encode_location(1, "T", "C:/\u00e9\ud800", "m")
        self.assertEqual(gs.decode_location(data), (1, "T", "C:/\u00e9\ud800", "m"))
        with self.assertRaises(gs.ProtocolError):
            gs.decode_location(b'["a","T","C:/a",null]')

    def test_private_scope_protocol_is_numeric_only(self):
        envelope = {"root_count": 2, "scopes": [[0, 7, 11, True], [1, 7, 12, False]]}
        data = gs.encode_scope(4, "0123456789abcdef", envelope)
        self.assertEqual(gs.decode_scope(data, 4)["envelope"], envelope)
        bad = [
            b'{"gen":4,"scan_id":"0123456789abcdef","envelope":{"root_count":1,"scopes":[],"path":"C:/leak"}}',
            b'{"gen":4,"scan_id":"0123456789abcdef","envelope":{"root_count":1,"scopes":[[0,1,2,false],[0,1,3,false]]}}',
            b'{"gen":5,"scan_id":"0123456789abcdef","envelope":{"root_count":0,"scopes":[]}}',
        ]
        for payload in bad:
            with self.assertRaises(gs.ProtocolError):
                gs.decode_scope(payload, 4)


class LocationStoreTests(unittest.TestCase):
    def test_generation_gate_and_clear(self):
        store = gs.LocationStore()
        self.assertFalse(store.put(1, "T", "C:/a", None))
        store.reset(1)
        self.assertTrue(store.put(1, "T", "C:/a", None))
        self.assertFalse(store.put(2, "U", "C:/b", None))
        self.assertEqual(store.get(1, "T"), ("C:/a", None))
        self.assertIsNone(store.get(2, "T"))
        store.reset(2)
        self.assertIsNone(store.get(2, "T"))
        store.put(2, "T", "C:/a", None)
        store.clear()
        self.assertEqual(len(store), 0)
        self.assertIsNone(store.get(2, "T"))

    def test_budgets(self):
        store = gs.LocationStore(limit=3, char_budget=50)
        store.reset(1)
        self.assertTrue(store.put(1, "A", "x" * 20, None))
        self.assertFalse(store.put(1, "A", "y", None))  # duplicate target ID
        self.assertTrue(store.put(1, "B", "x" * 20, None))
        self.assertFalse(store.put(1, "C", "x" * 20, None))  # char budget
        self.assertTrue(store.put(1, "D", "x", None))
        self.assertFalse(store.put(1, "E", "x", None))  # count limit
        self.assertFalse(store.put(1, "F", "a\x00b", None))
        self.assertEqual(store.rejected, 4)

    def test_concurrent_put_get(self):
        store = gs.LocationStore()
        store.reset(1)

        def writer(prefix):
            for i in range(2000):
                store.put(1, "%s%d" % (prefix, i), "C:/f", None)

        threads = [threading.Thread(target=writer, args=(p,)) for p in "ABCD"]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(store), 8000)


class SessionTests(unittest.TestCase):
    def make(self, target, store=None, **kwargs):
        kwargs.setdefault("result_validator", passthrough)
        session = gs.ScanSession(1, ["C:/synthetic/input.txt"], None, location_store=store, worker_target=target, **kwargs)
        self.addCleanup(self._cleanup, session)
        return session

    def _cleanup(self, session):
        session.close()
        self.assertTrue(session.reaped.wait(15), "session was not reaped")
        self.assertFalse(session.reap_failed)
        self.assertFalse(session.worker_alive())
        self.assertEqual(session.helper_threads_alive(), [])

    def test_result_progress_and_locations(self):
        store = gs.LocationStore()
        session = self.make(worker_result, store)
        self.assertTrue(session.start())
        events = run_until_finished(session)
        self.assertEqual(session.final["outcome"], "result")
        self.assertEqual(final_data(session), {"echo": 1})
        self.assertIn({"targets": 2}, events)
        deadline = time.monotonic() + 5
        while len(store) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(store.get(1, "T2"), ("C:/synthetic/input.txt", "inner/a.txt"))

    def test_cooperative_cancel_keeps_cancelled_result(self):
        session = self.make(worker_cooperative)
        session.start()
        time.sleep(0.5)
        self.assertTrue(session.cancel())
        run_until_finished(session)
        self.assertEqual(session.final["outcome"], "result")
        self.assertEqual(final_data(session), {"completeness": "cancelled"})

    def test_accepted_cancel_discards_complete_result_in_flight(self):
        session = self.make(worker_complete_result)
        session.start()
        deadline = time.monotonic() + 15
        while not session.has_pending_terminal() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(session.has_pending_terminal())
        # The complete result is already received but not yet polled: cancel wins.
        self.assertTrue(session.cancel())
        session.poll()
        self.assertEqual(session.final, {"outcome": "cancelled", "result": None, "code": None})

    def test_cancel_after_final_is_rejected(self):
        session = self.make(worker_complete_result)
        session.start()
        run_until_finished(session)
        self.assertEqual(session.final["outcome"], "result")
        self.assertFalse(session.cancel())
        self.assertEqual(final_data(session), {"completeness": "complete"})

    def test_strict_validator_failure_is_protocol_violation(self):
        called = []

        def reject(raw):
            called.append(raw)
            raise ValueError("bad")

        session = self.make(worker_complete_result, result_validator=reject)
        self.assertTrue(session.start())
        run_until_finished(session)
        self.assertEqual(session.final["code"], "protocol_violation")
        self.assertEqual(called, [{"completeness": "complete"}])

    def test_oversized_message_is_protocol_violation(self):
        session = self.make(worker_oversized)
        session.start()
        run_until_finished(session)
        self.assertEqual(session.final["code"], "protocol_violation")

    def test_forced_cancel_terminates_owned_worker(self):
        session = self.make(worker_ignore_cancel, cancel_grace=0.5, kill_grace=0.5)
        session.start()
        time.sleep(0.5)
        started = time.monotonic()
        session.cancel()
        run_until_finished(session)
        self.assertLess(time.monotonic() - started, 6.0)
        self.assertEqual(session.final["outcome"], "cancelled")

    def test_dead_worker_is_reported(self):
        session = self.make(worker_die)
        session.start()
        run_until_finished(session)
        self.assertEqual(session.final, {"outcome": "error", "result": None, "code": "worker_exited"})

    def test_partial_message_then_death_does_not_hang(self):
        session = self.make(worker_partial_then_die)
        session.start()
        run_until_finished(session, limit=30)
        # The point is "no hang": whether the pipe delivered the whole message
        # before the exit depends on timing, so both bounded outcomes are valid.
        self.assertTrue(session.finished)
        if session.final["outcome"] != "result":
            self.assertEqual(session.final["outcome"], "error")
            self.assertIn(session.final["code"], {"worker_exited", "protocol_violation"})

    def test_protocol_violations(self):
        for target in (worker_garbage, worker_wrong_generation, worker_extra_key):
            with self.subTest(target=target.__name__):
                session = self.make(target)
                session.start()
                run_until_finished(session)
                self.assertEqual(session.final["code"], "protocol_violation")

    def test_wall_timeout_covers_startup_and_hang(self):
        session = self.make(worker_ignore_cancel, wall_timeout=1.5)
        started = time.monotonic()
        session.start()
        run_until_finished(session)
        self.assertEqual(session.final["code"], "timeout")
        self.assertLess(time.monotonic() - started, 6.0)

    def test_large_result_is_received(self):
        session = self.make(worker_large_result)
        session.start()
        run_until_finished(session, limit=30)
        self.assertEqual(session.final["outcome"], "result")
        self.assertEqual(len(final_data(session)["blob"]), 8 * 1024 * 1024)

    def test_location_flood_is_capped(self):
        store = gs.LocationStore()
        session = self.make(worker_location_flood, store)
        session.start()
        run_until_finished(session, limit=60)
        self.assertEqual(session.final["outcome"], "result")
        deadline = time.monotonic() + 20
        while session.helper_threads_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(len(store), gs.MAX_LOCATIONS)
        self.assertIsNone(store.get(1, "OTHER"))

    def test_close_is_nonblocking_and_releases_hung_writer(self):
        store = gs.LocationStore()
        session = self.make(worker_hang_location_pipe, store, cancel_grace=0.5, kill_grace=0.5)
        session.start()
        time.sleep(0.8)
        started = time.monotonic()
        session.close()
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertTrue(session.reaped.wait(15))

    def test_repeated_cancel_does_not_accumulate_threads(self):
        baseline = threading.active_count()
        sessions = []
        for gen in range(1, 5):
            session = gs.ScanSession(gen, ["C:/x"], None, location_store=gs.LocationStore(),
                                     worker_target=worker_ignore_cancel, cancel_grace=0.3, kill_grace=0.5)
            session.start()
            session.cancel()
            session.close()
            session.close()  # immediate repeat is harmless
            sessions.append(session)
        for session in sessions:
            self.assertTrue(session.reaped.wait(15))
            self.assertFalse(session.reap_failed)
            self.assertFalse(session.worker_alive())
            self.assertEqual(session.helper_threads_alive(), [])
        deadline = time.monotonic() + 5
        while threading.active_count() > baseline and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertLessEqual(threading.active_count(), baseline)

    def test_start_failure_reports_fixed_code(self):
        session = gs.ScanSession(1, ["C:/x"], None, worker_target=worker_result)
        self.addCleanup(session.close)
        with mock.patch.object(session._ctx, "Process", side_effect=OSError("synthetic start failure")):
            self.assertFalse(session.start())
        self.assertEqual(session.final, {"outcome": "error", "result": None, "code": "start_failed"})
        self.assertTrue(session.reaped.is_set())


if __name__ == "__main__":
    unittest.main()
