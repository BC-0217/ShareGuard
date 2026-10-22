"""Background scan session used by the GUI.

This module never imports or calls Tk.  The scan runs in a separate process
started with the ``spawn`` method.  Three one-way pipes connect it to the GUI
process; the GUI closes its copy of each write end right after the spawn, so
a dead worker always produces EOF, even in the middle of a message:

* the result pipe carries only JSON text with a fixed, validated schema
  (progress counters, the sanitized ``ScanResult.to_dict()`` payload, or a
  fixed error code);
* the private location pipe carries JSON ``[generation, target_id,
  source_path, member_name_or_none]`` for the optional "reveal one location"
  feature.  Paths never travel on the result pipe;
* a third private pipe carries only the scan ID and numeric root identities
  needed to bind an explicit report export to the inputs that were scanned.

Threads: the GUI calls :meth:`ScanSession.poll` from its UI thread and it
never blocks.  A result drain thread reads, parses and strictly validates
worker messages into two bounded slots (latest progress, one terminal
outcome).  A location drain thread fills :class:`LocationStore`.  A reaper
thread joins and releases the worker after :meth:`ScanSession.close`.  None
of these helper threads touch Tk.
"""

from __future__ import annotations

import json
import math
import multiprocessing
import os
import threading
import time
from collections import namedtuple

# Bounds applied at the GUI boundary.  Results are bounded by the policy
# (<= 10,000 findings, issues and visited targets); 16 MiB leaves ample room.
MAX_RESULT_BYTES = 16 * 1024 * 1024
MAX_PROGRESS_BYTES = 4096
MAX_LOCATIONS = 20_000
MAX_LOCATION_STORE_CHARS = 8 * 1024 * 1024
MAX_TARGET_ID_CHARS = 128
MAX_PATH_CHARS = 32_767
MAX_MEMBER_CHARS = 4096
MAX_LOCATION_BYTES = 6 * (MAX_PATH_CHARS + MAX_MEMBER_CHARS + MAX_TARGET_ID_CHARS) + 64
MAX_SCOPE_BYTES = 2 * 1024 * 1024

STARTUP_GRACE_SECONDS = 5.0
DEFAULT_WALL_TIMEOUT = 120.0 + STARTUP_GRACE_SECONDS
DEFAULT_CANCEL_GRACE = 2.0
DEFAULT_KILL_GRACE = 2.0
EXIT_SETTLE_SECONDS = 1.0
DRAIN_POLL_SECONDS = 0.1

# Progress counters accepted from the worker; anything else (including the
# core's ``current_target`` label) is dropped by the worker and rejected by
# the GUI.
PROGRESS_FIELDS = ("targets", "entries", "bytes", "findings", "issues")

ERROR_CODES = frozenset(
    {
        "start_failed",
        "worker_import_failed",
        "worker_failed",
        "worker_exited",
        "result_too_large",
        "protocol_violation",
        "timeout",
        "unsupported_platform",
    }
)

STATE_RUNNING = "running"
STATE_CANCELLING = "cancelling"
STATE_FINISHED = "finished"

ValidatedResult = namedtuple("ValidatedResult", "scan_result data exit_code")


class ProtocolError(ValueError):
    """A message from the worker did not match the allowlisted schema."""


def _is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**53


def _is_uint64(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**64


def _reject_constant(name):
    raise ValueError("non-finite constant")


def sanitize_progress(payload):
    """Reduce a core progress payload to allowlisted non-negative counters."""
    counts = {}
    if isinstance(payload, dict):
        for key in PROGRESS_FIELDS:
            value = payload.get(key)
            if _is_count(value):
                counts[key] = value
    return counts


def _check_primitive_tree(value, depth=0):
    if depth > 32:
        raise ProtocolError("depth")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProtocolError("float")
        return
    if isinstance(value, list):
        for item in value:
            _check_primitive_tree(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("key")
            _check_primitive_tree(item, depth + 1)
        return
    raise ProtocolError("type")


def encode_message(message):
    return json.dumps(message, allow_nan=False, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def parse_message(data, generation):
    """Validate one result-pipe message and return it as a dict.

    Accepted shapes (exact key sets):
      {"type": "progress", "gen": int, "counts": {field: int}}
      {"type": "result", "gen": int, "result": {...}}
      {"type": "error", "gen": int, "code": <ERROR_CODES>}

    The ``result`` payload is only checked structurally here; the session
    then validates it strictly (see :func:`validate_core_result`).
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_RESULT_BYTES:
        raise ProtocolError("size")
    try:
        message = json.loads(bytes(data).decode("ascii"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ProtocolError("json") from exc
    if not isinstance(message, dict):
        raise ProtocolError("shape")
    if not _is_count(message.get("gen")) or message.get("gen") != generation:
        raise ProtocolError("generation")
    kind = message.get("type")
    if kind == "progress":
        counts = message.get("counts")
        if set(message) != {"type", "gen", "counts"} or len(data) > MAX_PROGRESS_BYTES:
            raise ProtocolError("progress")
        if not isinstance(counts, dict):
            raise ProtocolError("progress")
        for key, value in counts.items():
            if key not in PROGRESS_FIELDS or not _is_count(value):
                raise ProtocolError("progress")
        return message
    if kind == "result":
        if set(message) != {"type", "gen", "result"} or not isinstance(message["result"], dict):
            raise ProtocolError("result")
        _check_primitive_tree(message["result"])
        return message
    if kind == "error":
        if set(message) != {"type", "gen", "code"} or message["code"] not in ERROR_CODES:
            raise ProtocolError("error")
        return message
    raise ProtocolError("type")


def validate_core_result(raw):
    """Strictly validate a worker payload with the core schema.

    The payload must round-trip unchanged through ``ScanResult.from_dict`` /
    ``to_dict``; the exit code comes from the same rule the CLI uses.
    Raises ``ValueError`` (or any core validation error) otherwise.
    """
    from shareguard.cli import exit_code
    from shareguard.model import ScanResult

    scan_result = ScanResult.from_dict(raw)
    canonical = scan_result.to_dict()
    if canonical != raw:
        raise ValueError("result does not match the core schema")
    return ValidatedResult(scan_result, canonical, exit_code(scan_result))


def encode_location(generation, target_id, source_path, member):
    """Encode one location for the private pipe, or ``None`` if out of bounds."""
    if not (isinstance(target_id, str) and isinstance(source_path, str)):
        return None
    if member is not None and not isinstance(member, str):
        return None
    if not (0 < len(target_id) <= MAX_TARGET_ID_CHARS and 0 < len(source_path) <= MAX_PATH_CHARS):
        return None
    if member is not None and not (0 < len(member) <= MAX_MEMBER_CHARS):
        return None
    data = json.dumps([generation, target_id, source_path, member], ensure_ascii=True).encode("ascii")
    if len(data) > MAX_LOCATION_BYTES:
        return None
    return data


def decode_location(data):
    """Decode one location message; raise ``ProtocolError`` if malformed."""
    try:
        item = json.loads(bytes(data).decode("ascii"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ProtocolError("location") from exc
    if not (isinstance(item, list) and len(item) == 4 and _is_count(item[0])):
        raise ProtocolError("location")
    return tuple(item)


def _validate_scope_message(message, generation):
    if not isinstance(message, dict) or set(message) != {"gen", "scan_id", "envelope"}:
        raise ProtocolError("scope")
    if not _is_count(message["gen"]) or message["gen"] != generation:
        raise ProtocolError("scope")
    scan_id = message["scan_id"]
    if not (isinstance(scan_id, str) and len(scan_id) == 16 and all(c in "0123456789abcdef" for c in scan_id)):
        raise ProtocolError("scope")
    envelope = message["envelope"]
    if not isinstance(envelope, dict) or set(envelope) != {"root_count", "scopes"}:
        raise ProtocolError("scope")
    root_count, scopes = envelope["root_count"], envelope["scopes"]
    if not _is_count(root_count) or root_count > 10_000 or not isinstance(scopes, list) or len(scopes) > root_count:
        raise ProtocolError("scope")
    seen = set()
    for item in scopes:
        if not (isinstance(item, list) and len(item) == 4):
            raise ProtocolError("scope")
        index, device, identity, is_directory = item
        if (
            not _is_count(index)
            or index >= root_count
            or index in seen
            or not _is_uint64(device)
            or not _is_uint64(identity)
            or not isinstance(is_directory, bool)
        ):
            raise ProtocolError("scope")
        seen.add(index)
    return message


def encode_scope(generation, scan_id, envelope):
    """Encode the numeric-only private report-scope envelope."""
    message = _validate_scope_message(
        {"gen": generation, "scan_id": scan_id, "envelope": envelope}, generation
    )
    data = json.dumps(message, allow_nan=False, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(data) > MAX_SCOPE_BYTES:
        raise ProtocolError("scope")
    return data


def decode_scope(data, generation):
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_SCOPE_BYTES:
        raise ProtocolError("scope")
    try:
        message = json.loads(bytes(data).decode("ascii"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ProtocolError("scope") from exc
    return _validate_scope_message(message, generation)


class LocationStore:
    """GUI-process memory-only map of target ID -> (path, member).

    Entries are accepted only for the current generation and within count
    and total-character budgets.  ``reset`` and ``clear`` drop everything;
    nothing is ever written to disk.
    """

    def __init__(self, limit=MAX_LOCATIONS, char_budget=MAX_LOCATION_STORE_CHARS):
        self._lock = threading.Lock()
        self._entries = {}
        self._generation = None
        self._limit = limit
        self._char_budget = char_budget
        self._chars = 0
        self.rejected = 0

    def reset(self, generation):
        with self._lock:
            self._entries = {}
            self._generation = generation
            self._chars = 0
            self.rejected = 0

    def clear(self):
        with self._lock:
            self._entries = {}
            self._generation = None
            self._chars = 0

    def put(self, generation, target_id, source_path, member):
        with self._lock:
            if self._generation is None or generation != self._generation:
                return False
            valid = (
                isinstance(target_id, str)
                and 0 < len(target_id) <= MAX_TARGET_ID_CHARS
                and isinstance(source_path, str)
                and 0 < len(source_path) <= MAX_PATH_CHARS
                and "\x00" not in source_path
                and (member is None or (isinstance(member, str) and 0 < len(member) <= MAX_MEMBER_CHARS))
            )
            size = (len(source_path) + len(member or "") + len(target_id)) if valid else 0
            if (
                not valid
                or target_id in self._entries
                or len(self._entries) >= self._limit
                or self._chars + size > self._char_budget
            ):
                self.rejected += 1
                return False
            self._entries[target_id] = (source_path, member)
            self._chars += size
            return True

    def get(self, generation, target_id):
        with self._lock:
            if self._generation is None or generation != self._generation:
                return None
            return self._entries.get(target_id)

    def __len__(self):
        with self._lock:
            return len(self._entries)


# ---------------------------------------------------------------------------
# Worker process side.  Runs in the spawned child; never imports Tk.


def worker_main(generation, paths, policy_data, cancel_event, result_conn, location_conn, scope_conn):
    """Entry point of the spawned scan process."""

    def emit(message):
        result_conn.send_bytes(encode_message(message))

    try:
        try:
            from shareguard.policy import Policy
            from shareguard.scanner import scan_paths
            from shareguard.safeio import clear_result_scopes, export_result_scopes
        except Exception:
            emit({"type": "error", "gen": generation, "code": "worker_import_failed"})
            return

        last_progress = [0.0]

        def on_progress(payload):
            now = time.monotonic()
            if now - last_progress[0] < 0.2:
                return
            last_progress[0] = now
            try:
                emit({"type": "progress", "gen": generation, "counts": sanitize_progress(payload)})
            except Exception:
                pass

        def on_location(target_id, source_path, member_name):
            # Forward the current target only; nothing is retained here.
            try:
                data = encode_location(generation, target_id, os.fspath(source_path), member_name)
                if data is not None:
                    location_conn.send_bytes(data)
            except Exception:
                pass

        try:
            policy = Policy.from_dict(policy_data) if policy_data is not None else None
            result = scan_paths(
                list(paths),
                policy=policy,
                cancel_event=cancel_event,
                callback=on_progress,
                location_callback=on_location if location_conn is not None else None,
            )
            if scope_conn is not None:
                envelope = export_result_scopes(result.scan_id)
                if envelope is not None:
                    scope_conn.send_bytes(encode_scope(generation, result.scan_id, envelope))
                clear_result_scopes(result.scan_id)
            data = encode_message({"type": "result", "gen": generation, "result": result.to_dict()})
        except Exception:
            emit({"type": "error", "gen": generation, "code": "worker_failed"})
            return
        if len(data) > MAX_RESULT_BYTES:
            emit({"type": "error", "gen": generation, "code": "result_too_large"})
            return
        result_conn.send_bytes(data)
    finally:
        for conn in (scope_conn, location_conn, result_conn):
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# GUI process side.


class ScanSession:
    """Owns one worker process, its pipes, drain threads and reaper thread.

    Cancellation boundary: :meth:`cancel` is accepted only while no final
    outcome has been produced by :meth:`poll`.  Once accepted, a result that
    is not itself ``cancelled`` (for example a complete result that was
    already in flight) is discarded and the outcome is ``cancelled``.
    """

    def __init__(
        self,
        generation,
        paths,
        policy_data=None,
        *,
        location_store=None,
        wall_timeout=DEFAULT_WALL_TIMEOUT,
        cancel_grace=DEFAULT_CANCEL_GRACE,
        kill_grace=DEFAULT_KILL_GRACE,
        worker_target=None,
        result_validator=None,
        clock=time.monotonic,
    ):
        self.generation = generation
        self._paths = [os.fspath(p) for p in paths]
        self._policy_data = policy_data
        self._store = location_store
        self._wall_timeout = wall_timeout
        self._cancel_grace = cancel_grace
        self._kill_grace = kill_grace
        self._target = worker_target or worker_main
        self._validator = result_validator or validate_core_result
        self._clock = clock
        self._ctx = multiprocessing.get_context("spawn")
        self._process = None
        self._cancel_event = None
        self._result_conn = None
        self._location_conn = None
        self._scope_conn = None
        self._threads = []
        self._reaper = None
        self._lock = threading.Lock()
        self._progress = None
        self._terminal = None
        self._scope_message = None
        self._scope_received = threading.Event()
        self._stop = threading.Event()
        self.reaped = threading.Event()
        self.reap_failed = False
        self.state = STATE_RUNNING
        self._started_at = None
        self._cancel_at = None
        self._terminated_at = None
        self._exited_at = None
        self._cancel_requested = False
        self.export_ready = False
        self._final = None
        self._closed = False

    # -- lifecycle (UI thread; never blocks for long) -----------------------

    def start(self):
        self._started_at = self._clock()
        if self._store is not None:
            self._store.reset(self.generation)
        child_ends = []
        try:
            self._cancel_event = self._ctx.Event()
            self._result_conn, result_send = self._ctx.Pipe(duplex=False)
            child_ends.append(result_send)
            location_send = None
            if self._store is not None:
                self._location_conn, location_send = self._ctx.Pipe(duplex=False)
                child_ends.append(location_send)
            self._scope_conn, scope_send = self._ctx.Pipe(duplex=False)
            child_ends.append(scope_send)
            self._process = self._ctx.Process(
                target=self._target,
                args=(
                    self.generation,
                    self._paths,
                    self._policy_data,
                    self._cancel_event,
                    result_send,
                    location_send,
                    scope_send,
                ),
                name="shareguard-scan",
                daemon=True,
            )
            self._process.start()
        except Exception:
            for conn in child_ends:
                conn.close()
            self._finish("error", None, "start_failed")
            self.close()
            return False
        # The child owns duplicates; closing ours makes a dead child read as EOF.
        for conn in child_ends:
            conn.close()
        self._spawn_thread(self._drain_results, "shareguard-result-drain")
        if self._location_conn is not None:
            self._spawn_thread(self._drain_locations, "shareguard-location-drain")
        self._spawn_thread(self._drain_scope, "shareguard-scope-drain")
        return True

    def _spawn_thread(self, target, name):
        thread = threading.Thread(target=target, name=name, daemon=True)
        self._threads.append(thread)
        thread.start()

    def cancel(self):
        """Request cancellation; returns True if the request was accepted."""
        if self.state != STATE_RUNNING:
            return False
        self._cancel_requested = True
        self.state = STATE_CANCELLING
        self._cancel_at = self._clock()
        try:
            self._cancel_event.set()
        except Exception:
            pass
        return True

    def close(self, graceful=False):
        """Stop the session without blocking: cleanup runs on a reaper thread.

        With ``graceful=True`` (used right after a final result) the drain
        threads keep reading until the worker's pipes reach EOF, so locations
        already sent are kept.  Otherwise draining stops immediately.
        Safe to call repeatedly.  ``reaped`` is set only after the worker is
        confirmed dead and every helper thread has ended; otherwise
        ``reap_failed`` becomes True.
        """
        if self._closed:
            if not graceful:
                self._stop.set()
            return
        self._closed = True
        if not graceful:
            self._stop.set()
        if self._cancel_event is not None:
            try:
                self._cancel_event.set()
            except Exception:
                pass
        if self._process is None:
            self._release_handles()
            self.reaped.set()
            return
        self._reaper = threading.Thread(target=self._reap, name="shareguard-reaper", daemon=True)
        self._reaper.start()

    def _reap(self):
        process = self._process
        dead = False
        try:
            # A worker that already delivered its result normally exits on its own.
            process.join(0.5 if self._final and self._final["outcome"] == "result" else self._cancel_grace)
            if process.is_alive():
                process.terminate()
                process.join(self._kill_grace)
            if process.is_alive():
                process.kill()
                process.join(self._kill_grace)
            dead = not process.is_alive()
        except Exception:
            dead = False
        # With the worker gone, pending data drains and every recv reaches EOF.
        for thread in self._threads:
            thread.join(self._kill_grace)
        self._stop.set()
        for thread in self._threads:
            thread.join(self._kill_grace)
        self._release_handles()
        threads_done = not any(t.is_alive() for t in self._threads)
        if dead:
            try:
                process.close()
            except Exception:
                pass
        if dead and threads_done:
            self.reaped.set()
        else:
            self.reap_failed = True

    def _release_handles(self):
        for conn in (self._result_conn, self._location_conn, self._scope_conn):
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def helper_threads_alive(self):
        threads = list(self._threads)
        if self._reaper is not None:
            threads.append(self._reaper)
        return [t for t in threads if t.is_alive()]

    @property
    def finished(self):
        return self.state == STATE_FINISHED

    @property
    def final(self):
        """``None`` while running, else {"outcome", "result", "code"}.

        For ``outcome == "result"`` the ``result`` is a :class:`ValidatedResult`.
        """
        return self._final

    def worker_alive(self):
        process = self._process
        if process is None:
            return False
        try:
            return process.is_alive()
        except ValueError:
            return False

    def has_pending_terminal(self):
        """True once the drain thread holds a final message not yet polled."""
        with self._lock:
            return self._terminal is not None

    # -- polling (UI thread, non-blocking) ------------------------------------

    def poll(self):
        """Apply drained messages and deadlines; return the latest progress or None."""
        if self.state == STATE_FINISHED:
            return None
        now = self._clock()
        with self._lock:
            progress, self._progress = self._progress, None
            terminal = self._terminal

        if terminal is not None:
            kind, payload = terminal
            if kind == "result":
                if self._cancel_requested and payload.data.get("completeness") != "cancelled":
                    # Accepted cancel wins over a non-cancelled result in flight.
                    self._finish("cancelled", None, None)
                else:
                    self._finish("result", payload, None)
            else:
                self._finish("error", None, payload)
            return progress

        if now - self._started_at > self._wall_timeout:
            self._finish("error", None, "timeout")
            return progress

        alive = self.worker_alive()
        if self.state == STATE_CANCELLING and alive:
            if self._terminated_at is None and now - self._cancel_at > self._cancel_grace:
                self._process.terminate()
                self._terminated_at = now
            elif self._terminated_at is not None and now - self._terminated_at > self._kill_grace:
                self._process.kill()
        if not alive:
            if self._exited_at is None:
                self._exited_at = now
            elif now - self._exited_at > EXIT_SETTLE_SECONDS:
                if self._cancel_requested:
                    self._finish("cancelled", None, None)
                else:
                    self._finish("error", None, "worker_exited")
        return progress

    def _finish(self, outcome, result, code):
        if self.state == STATE_FINISHED:
            return
        self.state = STATE_FINISHED
        self._final = {"outcome": outcome, "result": result, "code": code}
        if outcome != "result":
            # Stop an app-owned worker that is still running; never blocks.
            if self._cancel_event is not None:
                try:
                    self._cancel_event.set()
                except Exception:
                    pass
            process = self._process
            if process is not None:
                try:
                    if process.is_alive():
                        process.terminate()
                except Exception:
                    pass

    # -- helper threads (never touch Tk) --------------------------------------

    def _set_terminal(self, kind, payload):
        with self._lock:
            if self._terminal is None:
                self._terminal = (kind, payload)

    def _drain_results(self):
        conn = self._result_conn
        while not self._stop.is_set():
            try:
                if not conn.poll(DRAIN_POLL_SECONDS):
                    continue
                data = conn.recv_bytes(MAX_RESULT_BYTES)
            except EOFError:
                break
            except Exception:
                # Oversized or corrupt message: the pipe is no longer trusted.
                self._set_terminal("error", "protocol_violation")
                break
            try:
                message = parse_message(data, self.generation)
                if message["type"] == "progress":
                    with self._lock:
                        merged = dict(self._progress or {})
                        merged.update(message["counts"])
                        self._progress = merged
                    continue
                if message["type"] == "error":
                    self._set_terminal("error", message["code"])
                else:
                    validated = self._validator(message["result"])
                    self.export_ready = self._import_scope_for(validated)
                    self._set_terminal("result", validated)
            except Exception:
                self._set_terminal("error", "protocol_violation")
            # Exactly one terminal message is expected; ignore anything after it.
            break

    def _drain_locations(self):
        conn = self._location_conn
        store = self._store
        while not self._stop.is_set():
            try:
                if not conn.poll(DRAIN_POLL_SECONDS):
                    continue
                data = conn.recv_bytes(MAX_LOCATION_BYTES)
            except Exception:
                # Closed, or an oversized message made the pipe unreadable.
                break
            try:
                generation, target_id, source_path, member = decode_location(data)
            except ProtocolError:
                continue
            if generation == self.generation:
                store.put(generation, target_id, source_path, member)

    def _drain_scope(self):
        """Receive one numeric-only export-scope envelope on its private pipe."""
        conn = self._scope_conn
        try:
            if conn.poll(self._wall_timeout):
                data = conn.recv_bytes(MAX_SCOPE_BYTES)
                message = decode_scope(data, self.generation)
                with self._lock:
                    self._scope_message = message
        except Exception:
            pass
        finally:
            self._scope_received.set()

    def _import_scope_for(self, validated):
        """Import scan-time numeric identities before a result becomes visible."""
        data = getattr(validated, "data", None)
        scan_id = data.get("scan_id") if isinstance(data, dict) else None
        if not isinstance(scan_id, str):
            return False
        self._scope_received.wait(EXIT_SETTLE_SECONDS)
        with self._lock:
            message = self._scope_message
        if message is None or message["scan_id"] != scan_id:
            return False
        try:
            from shareguard.safeio import import_result_scopes

            return bool(import_result_scopes(scan_id, message["envelope"]))
        except Exception:
            return False
