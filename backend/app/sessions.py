"""Investigation sessions: the capture kept encrypted on local disk for a while.

After an analysis the pcap is stored under ``config.SESSION_DIR`` encrypted
with a per-session AES-256-GCM key that only lives in this process. tshark
needs a plain file, so ``decrypted_pcap`` writes one (mode 0600) for the
duration of a single tool call and removes it afterwards. Sessions expire by
inactivity, by explicit delete, and never survive a restart: the key is gone,
so leftover files are unreadable and are purged at startup.
"""
from __future__ import annotations

import gzip
import os
import secrets
import struct
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .models import AnalysisResult, SessionInfo

_MAGIC = b"PCAS1"
_CHUNK = 4 * 1024 * 1024
_GZIP_PREFIX = b"\x1f\x8b"


@dataclass
class SessionUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    questions: int = 0


@dataclass
class Session:
    id: str
    principal_id: str
    filename: str
    pcap_bytes: int
    created_at: float
    last_used_at: float
    analysis: AnalysisResult
    content_allowed: bool = False
    messages: List[dict] = field(default_factory=list)
    usage: SessionUsage = field(default_factory=SessionUsage)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _enc_path: str = field(default="", repr=False)
    _key: bytes = field(default=b"", repr=False)

    def expires_at(self) -> float:
        return self.last_used_at + config.SESSION_TTL_MINUTES * 60


def _open_source(path: str):
    with open(path, "rb") as probe:
        head = probe.read(2)
    if head == _GZIP_PREFIX:
        return gzip.open(path, "rb")
    return open(path, "rb")


def _encrypt_to(source_path: str, dest_path: str, key: bytes) -> int:
    """Chunked AES-GCM: MAGIC || (len(4) || nonce(12) || ciphertext)*. Returns plain size."""
    aead = AESGCM(key)
    prefix = secrets.token_bytes(4)
    total = 0
    fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out, _open_source(source_path) as src:
        out.write(_MAGIC)
        index = 0
        while True:
            chunk = src.read(_CHUNK)
            if not chunk:
                break
            nonce = prefix + struct.pack(">Q", index)
            blob = aead.encrypt(nonce, chunk, _MAGIC)
            out.write(struct.pack(">I", len(blob)) + nonce + blob)
            total += len(chunk)
            index += 1
    return total


def _decrypt_to(enc_path: str, dest_fd: int, key: bytes) -> None:
    aead = AESGCM(key)
    with open(enc_path, "rb") as src, os.fdopen(dest_fd, "wb") as out:
        if src.read(len(_MAGIC)) != _MAGIC:
            raise ValueError("not a session capture")
        while True:
            header = src.read(4 + 12)
            if not header:
                break
            (length,) = struct.unpack(">I", header[:4])
            nonce = header[4:]
            out.write(aead.decrypt(nonce, src.read(length), _MAGIC))


class SessionStore:
    def __init__(self, directory: Optional[str] = None) -> None:
        self.directory = directory or config.SESSION_DIR
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        self._lock = threading.Lock()
        self._sessions: Dict[str, Session] = {}

    # ---- lifecycle -------------------------------------------------------
    def create(
        self,
        principal_id: str,
        pcap_path: str,
        filename: str,
        analysis: AnalysisResult,
    ) -> Session:
        self.cleanup()
        session_id = secrets.token_urlsafe(24)
        key = secrets.token_bytes(32)
        enc_path = os.path.join(self.directory, session_id + ".pcap.enc")
        try:
            size = _encrypt_to(pcap_path, enc_path, key)
        except Exception:
            self._remove_file(enc_path)
            raise
        now = time.time()
        session = Session(
            id=session_id,
            principal_id=principal_id,
            filename=filename,
            pcap_bytes=size,
            created_at=now,
            last_used_at=now,
            analysis=analysis,
            _enc_path=enc_path,
            _key=key,
        )
        with self._lock:
            self._sessions[session_id] = session
            self._enforce_limits_locked(keep=session_id)
        return session

    def get(self, session_id: str, principal_id: str) -> Optional[Session]:
        session = self.peek(session_id, principal_id)
        if session is not None:
            session.last_used_at = time.time()
        return session

    def peek(self, session_id: str, principal_id: str) -> Optional[Session]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.principal_id != principal_id:
                return None
            if session.expires_at() <= time.time():
                return None  # hidden now; cleanup() removes it and its file
            return session

    def delete(self, session_id: str, principal_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.principal_id != principal_id:
                return False
            self._drop_locked(session_id)
            return True

    @contextmanager
    def decrypted_pcap(self, session: Session) -> Iterator[str]:
        fd, path = tempfile.mkstemp(dir=self.directory, suffix=".pcap")
        try:
            os.chmod(path, 0o600)
            _decrypt_to(session._enc_path, fd, session._key)
            yield path
        finally:
            self._remove_file(path)

    # ---- housekeeping ----------------------------------------------------
    def cleanup(self) -> int:
        now = time.time()
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if s.expires_at() <= now]
            for sid in expired:
                self._drop_locked(sid)
            return len(expired) + self._enforce_limits_locked()

    def purge_orphans(self) -> int:
        removed = 0
        with self._lock:
            tracked = {s._enc_path for s in self._sessions.values()}
            for name in os.listdir(self.directory):
                path = os.path.join(self.directory, name)
                if path in tracked:
                    continue
                if name.endswith(".pcap.enc") or name.endswith(".pcap"):
                    self._remove_file(path)
                    removed += 1
        return removed

    def total_bytes(self) -> int:
        with self._lock:
            return sum(s.pcap_bytes for s in self._sessions.values())

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # ---- internals (caller holds self._lock) -----------------------------
    def _enforce_limits_locked(self, keep: Optional[str] = None) -> int:
        removed = 0
        while True:
            over_count = len(self._sessions) > config.MAX_SESSIONS
            over_bytes = sum(s.pcap_bytes for s in self._sessions.values()) > config.MAX_SESSION_BYTES
            if not (over_count or over_bytes):
                return removed
            victims = [s for sid, s in self._sessions.items() if sid != keep]
            if not victims:
                return removed
            idle = [s for s in victims if not s.lock.locked()]  # never kill a running turn first
            oldest = min(idle or victims, key=lambda s: s.last_used_at)
            self._drop_locked(oldest.id)
            removed += 1

    def _drop_locked(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is not None:
            self._remove_file(session._enc_path)

    @staticmethod
    def _remove_file(path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass


session_store = SessionStore()


def session_info(session: Session) -> SessionInfo:
    return SessionInfo(
        id=session.id,
        expires_at=session.expires_at(),
        ttl_minutes=config.SESSION_TTL_MINUTES,
        content_allowed=session.content_allowed,
    )
