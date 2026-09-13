#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mind.py — a local-only personal memory assistant, in one file.

WHAT IT DOES
    A background daemon captures the things you tell it to capture (clipboard,
    which app/window you're focused on, and text files in folders you choose),
    embeds them with a local Ollama model, and stores everything in a local
    SQLite database. A CLI chat then answers questions grounded in that
    history using hybrid retrieval (semantic vectors + BM25 keyword search,
    fused and recency-weighted).

    Nothing leaves your machine. The only network calls are to your local
    Ollama server. There is no telemetry, no cloud, no account.

    It does NOT fine-tune model weights. "Retention" is a retrieval window:
    old rows are deleted outright, so anything it knows can be deleted
    instantly and completely. That is deliberate — continuously retraining a
    model on personal data is slow, expensive, and effectively impossible to
    undo.

QUICK START
    python3 mind.py setup         # interactive: models, sources, retention
    python3 mind.py doctor        # verify everything works, with fixes
    python3 mind.py install       # run capture automatically at login
    python3 mind.py chat          # talk to it

    python3 mind.py capture       # run the daemon in the foreground instead
    python3 mind.py status        # what's enabled, what's stored, is it alive
    python3 mind.py search "kube" # grep your memory without invoking the LLM
    python3 mind.py pause/resume  # stop and start capture without uninstalling
    python3 mind.py encrypt on     # encrypt the database at rest
    python3 mind.py serve         # let your other machines ask this one
    python3 mind.py peer add laptop http://laptop:7717
    python3 mind.py forget --all  # delete everything it has stored
    python3 mind.py export --out mind.jsonl
    python3 mind.py selftest      # run the built-in test suite

PLATFORM NOTES
    Windows  clipboard and focus are read in-process via ctypes; autostart is a
             Task Scheduler logon task running pythonw.exe (no console window).
    macOS    clipboard via pbpaste, focus via osascript; autostart is a
             LaunchAgent. Two TCC permissions matter and they fail differently:
             without Automation (System Events) focus capture returns nothing,
             and without Accessibility you get app names but never window
             titles. Both are granted per BINARY, so permission you granted to
             Terminal does not transfer to the launchd-started interpreter --
             grant them to that interpreter too (`doctor` prints its path), and
             add Full Disk Access if you index folders under Desktop,
             Documents, or Downloads.
    Linux    clipboard via wl-paste/xclip/xsel, focus via xdotool (X11);
             autostart is a systemd --user unit.

REQUIREMENTS
    Python 3.8+ and a running Ollama server (https://ollama.com).
        ollama pull qwen2.5:7b          (or any chat model you like)
        ollama pull nomic-embed-text    (embeddings)

    No pip installs are required. numpy is used automatically if present and
    makes vector search several times faster (measured ~8 ms vs ~51 ms per
    query over 50,000 entries); without it the script falls back to a
    binary-quantized Hamming prefilter plus exact rerank, which stays
    comfortably fast into the tens of thousands of entries.

DESIGN NOTES
    - Capture producers are independent threads feeding one bounded queue.
      A single ingest worker batches them, embeds the batch in one request,
      and commits in one transaction. Capture never blocks on the model.
    - If Ollama is down, captures are still stored (without embeddings) and a
      maintenance thread backfills them once the server returns. You do not
      lose data because you restarted Ollama.
    - Embeddings are L2-normalized float32 blobs, so cosine similarity is a
      plain dot product. A 1-bit sign quantization of each vector is stored
      alongside for fast candidate filtering.
    - SQLite runs in WAL mode, so the chat can read while the daemon writes.

PRIVACY
    - Every source is off until you turn it on. `status` always shows exactly
      what is enabled.
    - This captures YOUR machine's activity for YOU. It deliberately includes
      no microphone, camera, or ambient capture: recording other people
      without their consent is a problem no amount of local storage solves.
    - Text that matches known credential patterns (API keys, private key
      headers, bearer tokens, password assignments) or that contains
      high-entropy secret-shaped tokens is dropped before it is stored.
    - Clipboard and window capture are suppressed entirely while a password
      manager (or any app on your denylist) is in the foreground, and window
      titles from private/incognito windows are skipped.
    - The data directory is created with owner-only permissions where the OS
      supports it.
    - `mind encrypt on` encrypts the database at rest with SQLCipher (AES-256
      over whole pages, so keyword search still works). The key lives in
      Windows DPAPI or the macOS Keychain so capture still starts at logon —
      or behind a passphrase you type, which is the only option that also
      defends against malware running as you, at the cost of unattended
      capture. Migration verifies every row and keeps a backup before it
      swaps anything.
    - Federated query keeps that promise across machines: peers hold their own
      data and answer their own questions, so nothing is ever pooled or
      uploaded. The peer endpoint is read-only, binds to loopback unless you
      give it a token, and is meant to be reached over Tailscale/WireGuard.
    - Encryption at rest is a second lock, not the first one: for a lost or
      stolen machine full-disk encryption (BitLocker / FileVault / LUKS) is
      what actually protects you. `doctor` tells you whether it is on.

LICENSE
    Public domain / CC0. Do whatever you want with it.
"""

from __future__ import annotations

import argparse
import contextlib
import concurrent.futures
import dataclasses
import hashlib
import hmac
import http.client
import http.server
import io
import json
import logging
import logging.handlers
import math
import os
import platform
import queue
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

APP_NAME = "mind"
VERSION = "2.21.0"
SCHEMA_VERSION = 1

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = not IS_WINDOWS and not IS_MACOS

# numpy is optional: used for fast vector math when available.
try:  # pragma: no cover - trivial import guard
    import numpy as _np

    HAVE_NUMPY = True
except Exception:  # pragma: no cover
    _np = None
    HAVE_NUMPY = False


# ==========================================================================
# Paths
# ==========================================================================

def default_home() -> Path:
    """Data directory. Override with the MIND_HOME environment variable."""
    env = os.environ.get("MIND_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".mind"


class Paths:
    """Resolved file locations for one MIND_HOME."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.config = home / "config.json"
        self.db = home / "mind.db"
        self.log = home / "mind.log"
        self.lock = home / "capture.lock"
        self.heartbeat = home / "heartbeat.json"
        self.paused = home / "paused"

    def ensure(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        # Owner-only where the platform supports POSIX modes.
        if not IS_WINDOWS:
            with contextlib.suppress(OSError):
                os.chmod(self.home, 0o700)


# ==========================================================================
# Console output
# ==========================================================================

class _NullStream:
    """Stand-in for a missing stdout (pythonw.exe gives you None)."""

    def write(self, _text: str) -> int:
        return 0

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


NULL_STREAM = _NullStream()


class Console:
    """Minimal ANSI console helper that degrades to plain text."""

    # Box-drawing and marks, with an ASCII fallback for consoles that cannot
    # encode them (legacy Windows code pages, redirected output, CI logs).
    _UNICODE_GLYPHS = {
        "ok": "✓", "warn": "!", "fail": "✗", "dot": "●", "ring": "○",
        "arrow": "→", "bullet": "·", "rule": "─", "vrule": "│",
        "full": "█", "empty": "░", "chev": "›",
    }
    _ASCII_GLYPHS = {
        "ok": "+", "warn": "!", "fail": "x", "dot": "*", "ring": "o",
        "arrow": "->", "bullet": "-", "rule": "-", "vrule": "|",
        "full": "#", "empty": ".", "chev": ">",
    }
    WIDTH = 66

    def __init__(self, stream=None) -> None:
        self._explicit = stream
        self.color = self._supports_color()
        self.unicode = self._supports_unicode()

    @property
    def stream(self):
        # Resolved lazily: under pythonw.exe sys.stdout is None, and the daemon
        # must still run rather than crash on its first write.
        return self._explicit or sys.stdout or NULL_STREAM

    def _supports_color(self) -> bool:
        if os.environ.get("NO_COLOR"):
            return False
        if not hasattr(self.stream, "isatty") or not self.stream.isatty():
            return False
        if IS_WINDOWS:
            return self._enable_windows_vt()
        return True

    @staticmethod
    def _enable_windows_vt() -> bool:
        """Turn on ANSI escape processing in the Windows console."""
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            return bool(
                kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
            )
        except Exception:
            return False

    def _supports_unicode(self) -> bool:
        """Can this console actually render box-drawing characters?

        Guessing wrong makes every screen worse than plain ASCII would have
        been, so this asks the stream's own encoding rather than assuming.
        Set MIND_ASCII=1 to force the plain set.
        """
        if os.environ.get("MIND_ASCII"):
            return False
        encoding = getattr(self.stream, "encoding", None) or "utf-8"
        try:
            "".join(self._UNICODE_GLYPHS.values()).encode(encoding)
            return True
        except (LookupError, UnicodeEncodeError, TypeError):
            return False

    def g(self, name: str) -> str:
        """One glyph, in whichever set this console can render."""
        table = self._UNICODE_GLYPHS if self.unicode else self._ASCII_GLYPHS
        return table.get(name, "")

    def _wrap(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def bold(self, t: str) -> str:
        return self._wrap(t, "1")

    def dim(self, t: str) -> str:
        return self._wrap(t, "2")

    def green(self, t: str) -> str:
        return self._wrap(t, "32")

    def yellow(self, t: str) -> str:
        return self._wrap(t, "33")

    def red(self, t: str) -> str:
        return self._wrap(t, "31")

    def cyan(self, t: str) -> str:
        return self._wrap(t, "36")

    def write(self, text: str = "") -> None:
        self.stream.write(text + "\n")
        self.stream.flush()

    def raw(self, text: str) -> None:
        self.stream.write(text)
        self.stream.flush()

    # -- status marks ------------------------------------------------------
    def ok(self, text: str) -> None:
        self.write(f"  {self.green(self.g('ok'))}  {text}")

    def warn(self, text: str) -> None:
        self.write(f"  {self.yellow(self.g('warn'))}  {text}")

    def fail(self, text: str) -> None:
        self.write(f"  {self.red(self.g('fail'))}  {text}")

    def info(self, text: str) -> None:
        self.write(f"  {self.dim(self.g('bullet'))}  {self.dim(text)}")

    def mark(self, state: Optional[bool]) -> str:
        """A coloured tick / cross / dash for a tri-state check."""
        if state is True:
            return self.green(self.g("ok"))
        if state is False:
            return self.red(self.g("fail"))
        return self.dim(self.g("bullet"))

    # -- layout ------------------------------------------------------------
    def header(self, text: str) -> None:
        self.write("")
        self.write(self.bold(text))

    def title(self, text: str, right: str = "") -> None:
        """The top line of a screen: name on the left, context on the right."""
        self.write("")
        left = f"  {self.bold(text)}"
        if right:
            pad = max(1, self.WIDTH - len(text) - len(right))
            left += " " * pad + self.dim(right)
        self.write(left)

    def section(self, text: str) -> None:
        """A titled band with a rule under it."""
        self.write("")
        self.write(f"  {self.bold(text.upper())}")
        self.write(f"  {self.dim(self.g('rule') * self.WIDTH)}")

    def rule(self) -> None:
        self.write(f"  {self.dim(self.g('rule') * self.WIDTH)}")

    def kv(self, key: str, value: str, hint: str = "", key_width: int = 13) -> None:
        """An aligned label/value row. Pad before colouring — ANSI codes count
        as characters to ljust() and would wreck the column."""
        line = f"  {self.dim(key.ljust(key_width))} {value}"
        if hint:
            line += f"   {self.dim(hint)}"
        self.write(line)

    def note(self, text: str, key_width: int = 13) -> None:
        """A dim continuation line under the previous kv row."""
        self.write(f"  {' ' * key_width} {self.dim(text)}")

    def sub(self, text: str) -> None:
        """A dim continuation line under an ok/warn/fail mark, aligned to its
        text column rather than floating a couple of spaces off it."""
        self.write(f"     {self.dim(text)}")

    def bar(self, fraction: float, width: int = 18) -> str:
        filled = max(0, min(width, int(round(fraction * width))))
        return self.cyan(self.g("full") * filled) + self.dim(self.g("empty") * (width - filled))


_ORIGINAL_CONSOLE_CP: Optional[int] = None


def _enable_windows_utf8_console() -> None:
    """Switch a legacy Windows console to UTF-8 for the life of this process.

    Windows consoles default to code page 437/1252. Our output is UTF-8, so
    without this an em dash renders as 'ΓÇö' and emoji as line noise — the
    stored data is fine, only the terminal mangles it. The previous code page
    is restored at exit so the user's shell is left as we found it.
    """
    global _ORIGINAL_CONSOLE_CP
    try:
        import atexit
        import ctypes

        kernel32 = ctypes.windll.kernel32
        current = kernel32.GetConsoleOutputCP()
        if not current or current == 65001:
            return  # no console (pythonw) or already UTF-8
        if not kernel32.SetConsoleOutputCP(65001):
            return
        _ORIGINAL_CONSOLE_CP = int(current)

        def _restore() -> None:
            with contextlib.suppress(Exception):
                kernel32.SetConsoleOutputCP(_ORIGINAL_CONSOLE_CP)

        atexit.register(_restore)
    except Exception:
        pass


class Spinner:
    """A lightweight status animation for the phases that can't stream.

    Tool-calling turns return their whole payload at once, so there is nothing
    to stream while the model is deciding what to do or a tool is running. The
    spinner fills that gap: a braille cycle plus a phase label ('thinking',
    'searching the web', 'reading 3 sources'). On a non-tty it prints each new
    phase once as a plain line instead of animating.
    """

    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, console: "Console", label: str = "thinking") -> None:
        self.console = console
        self._label = label
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._animate = console.color and _stream_is_tty(console.stream)
        self._last_plain = ""
        self._width = 0

    def set_label(self, label: str) -> None:
        with self._lock:
            if label == self._label:
                return
            self._label = label
        if not self._animate:
            self.console.write(self.console.dim(f"  … {label}"))

    def start(self) -> None:
        if not self._animate:
            self.console.write(self.console.dim(f"  … {self._label}"))
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        index = 0
        while not self._stop.is_set():
            with self._lock:
                label = self._label
            frame = self.FRAMES[index % len(self.FRAMES)]
            text = f"  {frame} {label}"
            self._width = max(self._width, len(text))
            with contextlib.suppress(Exception):
                self.console.stream.write("\r" + text.ljust(self._width))
                self.console.stream.flush()
            index += 1
            self._stop.wait(0.09)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if self._animate:
            with contextlib.suppress(Exception):
                # Erase the spinner line so the answer starts clean.
                self.console.stream.write("\r" + " " * max(self._width, 1) + "\r")
                self.console.stream.flush()


def _stream_is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def configure_stdio() -> None:
    """Force UTF-8 on stdout/stderr so Windows code pages don't mangle output."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:  # pythonw.exe: no console attached
            setattr(sys, stream_name, NULL_STREAM)
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")
    if IS_WINDOWS:
        _enable_windows_utf8_console()


CONSOLE = Console()


# ==========================================================================
# Configuration
# ==========================================================================

DEFAULT_CONFIG: Dict[str, Any] = {
    "ollama_url": "http://127.0.0.1:11434",
    "chat_model": "",
    "embed_model": "nomic-embed-text",
    "retention_days": 30,
    "max_entries": 200_000,
    "sources": {
        "clipboard": {
            "enabled": False,
            "poll_sec": 1.5,
            "min_chars": 12,
            "max_chars": 20_000,
        },
        "focus": {
            "enabled": False,
            "poll_sec": 2.0,
            "min_seconds": 8,
        },
        "browser": {
            "enabled": False,
            "browsers": ["firefox", "chrome", "edge", "brave", "safari", "arc",
                         "vivaldi", "opera"],
            "poll_sec": 60,
            "batch": 500,
            # YouTube's video id lives in ?v=, so a blanket query strip would
            # make every video URL unusable. Everything else is tracking junk
            # that can carry session tokens.
            "strip_query": True,
            "keep_params": {
                "youtube.com": ["v", "t", "list"],
                "youtu.be": ["t"],
                "google.com": ["q"],
                "wikipedia.org": [],
            },
            "domain_denylist": [],
        },
        "files": {
            "enabled": False,
            "folders": [],
            "extensions": [
                ".txt", ".md", ".markdown", ".rst", ".org",
                ".py", ".js", ".ts", ".go", ".rs", ".c", ".h", ".cpp", ".hpp",
                ".java", ".rb", ".sh", ".ps1", ".sql", ".yaml", ".yml", ".toml",
                ".ini", ".cfg", ".json", ".csv", ".log",
            ],
            "exclude_dirs": [
                ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv",
                "venv", "env", "dist", "build", "target", ".next", ".cache",
                "site-packages", ".idea", ".vscode", ".gradle", "vendor",
            ],
            "scan_interval_sec": 300,
            "max_file_bytes": 4_000_000,
            "max_files": 20_000,
        },
    },
    "privacy": {
        "skip_secrets": True,
        "entropy_guard": True,
        "app_denylist": [
            "keepass", "keepassxc", "1password", "bitwarden", "lastpass",
            "dashlane", "keeper", "enpass", "nordpass", "protonpass",
            "seahorse", "gnome-keyring", "kwalletmanager", "credential manager",
            "windows security", "authy",
        ],
        "title_denylist": [
            "incognito", "inprivate", "private browsing", "private window",
        ],
    },
    "network": {
        # Off by default. Turning it on lets the assistant fetch pages you or
        # your own history supplied — it never sends your captured data out.
        "enabled": False,
        "allow_search": True,
        "timeout_sec": 10,
        "max_bytes": 1_000_000,
        "max_redirects": 3,
        "domain_denylist": [],
        "user_agent": f"{APP_NAME}/{VERSION} (local personal assistant)",
        # Search engines reject unfamiliar clients; only search requests use this.
        "search_user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/126.0.0.0 Safari/537.36"),
        # Search backends tried in order. Any one being blocked on your network
        # is skipped, not fatal — that single-backend fragility is what used to
        # make research collapse to Wikipedia. Run `netcheck` to see which work.
        "search_engines": ["duckduckgo-lite", "duckduckgo-html", "bing", "mojeek"],
        # Optional self-hosted/public SearXNG instances (JSON API). When set,
        # they are tried first — the most reliable option on locked-down
        # networks. Example: ["https://searx.be"].
        "searxng_instances": [],
        # Open this many extra candidate pages per research pass and keep the
        # ones that actually read, so a couple of bot-blocked or JS-only pages
        # can't reduce a pass to "could not read any of them".
        "source_overfetch": 3,
        # Reader-mode extraction: keep the article, drop nav/cookie/sidebar
        # boilerplate before it reaches the model's context window.
        "readable_extraction": True,
    },
    "knowledge": {
        # Cache of things looked up on the web. Short-lived on purpose: the
        # point is to avoid re-fetching the same fact minutes apart, not to
        # build a stale second brain.
        "enabled": True,
        "auto_research": True,
        "ttl_sec": 86400,            # 24h default
        "volatile_ttl_sec": 3600,    # 1h for prices, "latest", "who is now"
        "stable_ttl_sec": 604800,    # 7d for plots, definitions, history
        "model_cutoff_year": 2024,   # a year >= this is a guaranteed gap
        "max_sources": 3,
        # Deep research: instead of one search-and-read pass, the assistant
        # reads what it found, decides whether it actually answers the
        # question, and searches again to fill the gaps -- the way you would.
        # Bounded on every axis so it can never run away.
        "deep_research": True,
        "max_rounds": 2,             # extra rounds after the first pass
        "deep_max_followups": 2,     # follow-up queries considered per round
        "deep_max_total_sources": 8, # hard cap on pages opened across all rounds
        "deep_digest_chars": 9000,   # total size of the combined digest; per-source
                                     # detail shrinks as sources grow so a deep
                                     # investigation never overruns the model's context
    },
    "profile": {
        # The consolidation layer: distils durable facts about you from your
        # captures and injects them into every answer. Runs nightly.
        "enabled": True,
        "inject": True,
        "reflect_interval_sec": 86400,   # once a day thereafter
        "first_reflect_sec": 900,        # but the FIRST pass lands in ~15 min
        "min_observations": 5,           # skip a pass with too little new material
        "max_observations": 200,         # cap fed to the model per pass
        "max_facts": 200,                # cap stored; weakest inferred ones evicted
        "half_life_days": 30.0,          # a fact's weight halves after this if unseen
        "min_confidence": 0.4,           # decayed below this -> pruned
        "dedup_threshold": 0.86,         # cosine similarity that counts as "same fact"
    },
    "agent": {
        "enabled": True,
        "max_steps": 6,
        "tool_result_chars": 4000,
    },
    "peers": {
        # Federated query. Other machines you own keep their OWN captures and
        # their OWN database; this one asks them a question and merges the
        # answers. Nothing is uploaded, nothing is pooled, and every result
        # says which machine it came from.
        #
        # The transport is deliberately dumb: plain HTTP bound to loopback,
        # meant to be reached over Tailscale/WireGuard rather than exposed.
        # Binding to a non-loopback address without a token is refused.
        "enabled": False,
        "node_name": "",             # defaults to this machine's hostname
        "serve_host": "127.0.0.1",
        "serve_port": 7717,
        "token": "",                 # shared secret; `mind peer token --new`
        "nodes": [],                 # [{"name": "laptop", "url": "http://laptop:7717"}]
        "timeout_sec": 8.0,
        # A peer answers with its own embeddings over its own index, so peers
        # need not agree on an embedding model -- only on the question text.
        "peer_top_k": 6,             # results requested from each peer
        "max_top_k": 25,             # ceiling this node will serve
        "max_query_chars": 512,      # ceiling on an inbound query
    },
    "retrieval": {
        "top_k": 8,
        "candidates": 400,
        "context_chars": 8_000,
        "rrf_k": 60,
        "half_life_days": 14.0,
        "recency_weight": 0.35,
        "min_score": 0.0,
    },
    "runtime": {
        "embed_batch": 16,
        "batch_window_sec": 2.0,
        "queue_max": 5_000,
        "max_vectors": 150_000,
        "log_level": "INFO",
        # Ollama defaults to a small context (often 4096, sometimes 2048) and
        # silently drops tokens off the FRONT of an oversized prompt -- which
        # eats the system prompt and the earliest context snippets. Always set
        # it explicitly. Raise for more retrieved context, lower if the KV
        # cache pushes a big model out of VRAM.
        "num_ctx": 8192,
        "summary_sec": 300.0,
        # Ceiling on embeddings per minute. Stops a bulk import (turning on
        # browser history, pointing at a big folder) from pinning the GPU.
        "max_embeds_per_min": 300,
        "http_timeout_sec": 120,
        "chat_timeout_sec": 600,
    },
}


if IS_MACOS:
    # Every clipboard/focus read on macOS spawns a helper process (pbpaste,
    # osascript). On a laptop that is a battery consideration, so poll less
    # often than on Windows, where both reads are in-process ctypes calls.
    DEFAULT_CONFIG["sources"]["clipboard"]["poll_sec"] = 2.0
    DEFAULT_CONFIG["sources"]["focus"]["poll_sec"] = 3.0


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    """Dictionary-backed config with dotted access and validation."""

    def __init__(self, data: Optional[Dict[str, Any]] = None) -> None:
        self.data = _deep_merge(json.loads(json.dumps(DEFAULT_CONFIG)), data or {})

    # -- persistence -------------------------------------------------------
    @classmethod
    def load(cls, paths: Paths) -> "Config":
        if not paths.config.exists():
            return cls()
        try:
            with open(paths.config, "r", encoding="utf-8") as fh:
                return cls(json.load(fh))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"could not read {paths.config}: {exc}") from exc

    def save(self, paths: Paths) -> None:
        paths.ensure()
        tmp = paths.config.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, sort_keys=False)
        tmp.replace(paths.config)
        if not IS_WINDOWS:
            with contextlib.suppress(OSError):
                os.chmod(paths.config, 0o600)

    # -- access ------------------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            if not isinstance(node, dict):
                raise ConfigError(f"{dotted} is not a settable path")
        node[parts[-1]] = value

    def validate(self) -> List[str]:
        """Return a list of human-readable problems (empty means valid)."""
        problems: List[str] = []
        url = self.get("ollama_url", "")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            problems.append(f"ollama_url is not a valid URL: {url!r}")
        if int(self.get("retention_days", 0)) < 1:
            problems.append("retention_days must be >= 1")
        if not self.get("embed_model"):
            problems.append("embed_model is empty")
        for name in ("clipboard", "focus", "files"):
            if not isinstance(self.get(f"sources.{name}"), dict):
                problems.append(f"sources.{name} is malformed")
        folders = self.get("sources.files.folders", [])
        if not isinstance(folders, list):
            problems.append("sources.files.folders must be a list")
        if int(self.get("retrieval.top_k", 0)) < 1:
            problems.append("retrieval.top_k must be >= 1")
        nodes = self.get("peers.nodes", [])
        if not isinstance(nodes, list):
            problems.append("peers.nodes must be a list")
        try:
            port = int(self.get("peers.serve_port", 0))
        except (TypeError, ValueError):
            port = 0
        if not 1 <= port <= 65535:
            problems.append("peers.serve_port must be between 1 and 65535")
        return problems

    def enabled_sources(self) -> List[str]:
        out = []
        if self.get("sources.clipboard.enabled"):
            out.append("clipboard")
        if self.get("sources.focus.enabled"):
            out.append("focus")
        if self.get("sources.files.enabled") and self.get("sources.files.folders"):
            out.append("files")
        if self.get("sources.browser.enabled"):
            out.append("browser")
        return out


class MindError(Exception):
    """Base class for expected, user-facing failures."""


class ConfigError(MindError):
    pass


class OllamaError(MindError):
    pass


class StorageError(MindError):
    pass


# ==========================================================================
# Logging
# ==========================================================================

def setup_logging(paths: Paths, level: str = "INFO", console: bool = False) -> logging.Logger:
    paths.ensure()
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(threadName)-14s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            paths.log, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError:
        pass

    if console:
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s",
                                                      datefmt="%H:%M:%S"))
        logger.addHandler(stream_handler)
    return logger


LOG = logging.getLogger(APP_NAME)


# ==========================================================================
# Small utilities
# ==========================================================================

def now_ts() -> float:
    return time.time()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def human_age(ts: float, now: Optional[float] = None) -> str:
    delta = max(0.0, (now if now is not None else now_ts()) - ts)
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()


def normalize_ws(text: str) -> str:
    """Collapse whitespace and strip control characters."""
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or unicodedata.category(ch)[0] != "C")
    return re.sub(r"[ \t]+", " ", text).strip()


def chunk_text(text: str, size: int = 1200, overlap: int = 150) -> List[str]:
    """Split text into overlapping chunks, preferring paragraph/line breaks."""
    text = text.strip()
    if not text:
        return []
    if len(text) <= size:
        return [text]

    chunks: List[str] = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + size, n)
        if end < n:
            window = text[start:end]
            for sep in ("\n\n", "\n", ". ", " "):
                idx = window.rfind(sep)
                if idx > size * 0.5:
                    end = start + idx + len(sep)
                    break
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= n:
            break
        start = max(end - overlap, start + 1)
    return chunks


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ==========================================================================
# Redaction / secret detection
# ==========================================================================

SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b")),
    ("stripe-key", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}")),
    ("basic-auth-url", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@")),
    ("assignment", re.compile(
        r"(?i)\b(?:api[_\-]?key|secret|passwd|password|pwd|token|auth|credential|private[_\-]?key)"
        r"\b\s*[:=]\s*[\"']?\S{8,}")),
    ("connection-string", re.compile(r"(?i)\b(?:password|pwd)\s*=\s*[^;\s]{6,}\s*;")),
    ("card-number", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("ssh-key", re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{40,}")),
]

_HIGH_ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")


def luhn_valid(digits: str) -> bool:
    """Card-number sanity check, so long numeric IDs aren't all treated as cards."""
    digits = re.sub(r"[^\d]", "", digits)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for idx, ch in enumerate(digits):
        digit = int(ch)
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class Redactor:
    """Decides whether captured text is safe to store."""

    def __init__(self, skip_secrets: bool = True, entropy_guard: bool = True,
                 entropy_threshold: float = 4.2) -> None:
        self.skip_secrets = skip_secrets
        self.entropy_guard = entropy_guard
        self.entropy_threshold = entropy_threshold

    def reason(self, text: str) -> Optional[str]:
        """Return the name of the rule that rejects this text, or None."""
        if not self.skip_secrets:
            return None
        for name, pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            if name == "card-number":
                if luhn_valid(match.group(0)):
                    return name
                continue
            return name
        if self.entropy_guard:
            for token in _HIGH_ENTROPY_TOKEN.findall(text):
                # Long random-looking blobs are usually keys, not prose.
                if shannon_entropy(token) >= self.entropy_threshold:
                    return "high-entropy-token"
        return None

    def is_safe(self, text: str) -> bool:
        return self.reason(text) is None


# ==========================================================================
# Encryption at rest
# ==========================================================================
#
# Threat model, stated plainly so nobody oversells this:
#
#   stolen laptop, powered off   -> full-disk encryption is the real defence;
#                                   this adds a second lock on top
#   another account on the box   -> yes, this helps
#   the DB in a backup / sync    -> yes, this is the strongest win
#   malware running AS YOU while
#   the capture daemon is up     -> NO. The daemon must decrypt to write, so
#                                   whatever key it can reach, malware can too.
#
# The passphrase provider is the one answer to that last row: capture can run
# unattended under a machine-held key, while *reading* your history requires a
# human. Choose deliberately.
#
# Design: SQLCipher encrypts whole database pages, so SQLite still sees
# plaintext in memory and FTS5 keyword search keeps working. Encrypting the
# text column at the application layer instead would have silently destroyed
# half of hybrid retrieval (BM25) and left the FTS index itself in the clear.

try:  # pragma: no cover - optional native dependency
    import sqlcipher3 as _sqlcipher

    HAVE_SQLCIPHER = True
except Exception:  # pragma: no cover
    _sqlcipher = None
    HAVE_SQLCIPHER = False

# sqlcipher3 raises its OWN exception classes; they do not inherit from
# sqlite3's. Every `except sqlite3.Error` in this file would silently miss them
# and crash, so all database error handling goes through this tuple.
DB_ERRORS: Tuple[type, ...] = (
    (sqlite3.Error, _sqlcipher.Error) if _sqlcipher is not None else (sqlite3.Error,))

# Install note: use `sqlcipher3`, NOT `sqlcipher3-binary` — the latter only
# publishes Linux wheels, so it tries to compile from source on Windows/macOS.
SQLCIPHER_MISSING = (
    "encryption needs the sqlcipher3 module, which is not installed.\n"
    "    pip install sqlcipher3\n"
    "    (if that has no wheel for your Python, try: pip install sqlcipher3-wheels)")


class KeyProviderError(MindError):
    """The key could not be created, stored, or retrieved."""


def _hex_key_pragma(key: bytes) -> str:
    """A raw-key PRAGMA. Passing raw bytes skips SQLCipher's own KDF, which is
    correct here: our keys are already 32 bytes of CSPRNG output or scrypt."""
    return "PRAGMA key = \"x'" + key.hex() + "'\""


# ==========================================================================
# Key providers — where the key actually lives
# ==========================================================================

class KeyProvider:
    """Custody of the 32-byte database key.

    Subclasses decide *where* it lives. None of them invent cryptography: the
    platform (DPAPI, Keychain) or a vetted KDF (scrypt) does that work.
    """

    name = "base"
    description = ""
    #: True when the key can be fetched with no human present (daemon-safe).
    unattended = True

    def __init__(self, paths: "Paths") -> None:
        self.paths = paths

    def available(self) -> bool:
        return False

    def exists(self) -> bool:
        raise NotImplementedError

    def create(self) -> bytes:
        raise NotImplementedError

    def load(self) -> bytes:
        raise NotImplementedError

    def destroy(self) -> None:
        raise NotImplementedError

    def verify(self) -> bool:
        """Round-trip the key before anything is encrypted with it.

        This is the guard against the worst possible outcome: storing a key
        through a mechanism that cannot read it back, having already encrypted
        the only copy of the data.
        """
        try:
            return len(self.load()) == 32
        except (KeyProviderError, OSError):
            return False


class DPAPIKeyProvider(KeyProvider):
    """Windows: wrap the key with DPAPI, tied to this Windows user account.

    Nothing to remember and no prompt, so the capture daemon starts at logon
    unattended. The wrapped blob is useless on another account or machine.
    """

    name = "dpapi"
    description = "Windows DPAPI (tied to your Windows account, no passphrase)"
    unattended = True

    @property
    def blob_path(self) -> Path:
        return self.paths.home / "key.dpapi"

    def available(self) -> bool:
        return IS_WINDOWS

    def exists(self) -> bool:
        return self.blob_path.exists()

    # -- ctypes plumbing ---------------------------------------------------
    def _dpapi(self, data: bytes, protect: bool) -> bytes:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD),
                        ("pbData", ctypes.POINTER(ctypes.c_char))]

        crypt32 = ctypes.WinDLL("crypt32.dll")
        kernel32 = ctypes.WinDLL("kernel32.dll")
        buffer_in = ctypes.create_string_buffer(data, len(data))
        blob_in = DATA_BLOB(len(data),
                            ctypes.cast(buffer_in, ctypes.POINTER(ctypes.c_char)))
        blob_out = DATA_BLOB()
        # CRYPTPROTECT_UI_FORBIDDEN: never show UI, so a headless daemon fails
        # loudly instead of hanging on an invisible prompt.
        flags = 0x1
        if protect:
            ok = crypt32.CryptProtectData(
                ctypes.byref(blob_in), ctypes.c_wchar_p(f"{APP_NAME} database key"),
                None, None, None, flags, ctypes.byref(blob_out))
        else:
            ok = crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, flags,
                ctypes.byref(blob_out))
        if not ok:
            raise KeyProviderError(
                f"DPAPI {'protect' if protect else 'unprotect'} failed "
                f"(Windows error {ctypes.get_last_error() or kernel32.GetLastError()})")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            with contextlib.suppress(Exception):
                kernel32.LocalFree(blob_out.pbData)

    def create(self) -> bytes:
        key = os.urandom(32)
        self.paths.home.mkdir(parents=True, exist_ok=True)
        self.blob_path.write_bytes(self._dpapi(key, protect=True))
        return key

    def load(self) -> bytes:
        if not self.blob_path.exists():
            raise KeyProviderError(f"no DPAPI key blob at {self.blob_path}")
        return self._dpapi(self.blob_path.read_bytes(), protect=False)

    def destroy(self) -> None:
        with contextlib.suppress(OSError):
            self.blob_path.unlink()


class KeychainKeyProvider(KeyProvider):
    """macOS: store the key in the login Keychain via the `security` tool."""

    name = "keychain"
    description = "macOS Keychain (tied to your login, no passphrase)"
    unattended = True
    SERVICE = f"{APP_NAME}-database-key"

    def _account(self) -> str:
        return os.environ.get("USER") or APP_NAME

    def available(self) -> bool:
        return IS_MACOS and bool(shutil.which("security"))

    def exists(self) -> bool:
        try:
            self.load()
            return True
        except KeyProviderError:
            return False

    def create(self) -> bytes:
        key = os.urandom(32)
        result = subprocess.run(
            ["security", "add-generic-password", "-U", "-a", self._account(),
             "-s", self.SERVICE, "-w", key.hex()],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise KeyProviderError(f"could not write to Keychain: {result.stderr.strip()[:160]}")
        return key

    def load(self) -> bytes:
        result = subprocess.run(
            ["security", "find-generic-password", "-a", self._account(),
             "-s", self.SERVICE, "-w"],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise KeyProviderError("no key in Keychain (or access was denied)")
        try:
            return bytes.fromhex(result.stdout.strip())
        except ValueError as exc:
            raise KeyProviderError("Keychain entry is not a valid key") from exc

    def destroy(self) -> None:
        subprocess.run(["security", "delete-generic-password", "-a", self._account(),
                        "-s", self.SERVICE], capture_output=True)


class PassphraseKeyProvider(KeyProvider):
    """A passphrase you type, stretched with scrypt. The key is never stored.

    This is the only provider that defends against malware running as you,
    because there is nothing on disk to steal — but it also means the capture
    daemon cannot start unattended.
    """

    name = "passphrase"
    description = "passphrase you type (strongest; capture cannot auto-start)"
    unattended = False
    # ~64MB of memory per attempt: painful to brute-force, fine to type.
    SCRYPT_N = 2 ** 16
    SCRYPT_R = 8
    SCRYPT_P = 1

    def __init__(self, paths: "Paths",
                 prompt: Optional[Callable[[str], str]] = None) -> None:
        super().__init__(paths)
        self._prompt = prompt
        self._cached: Optional[bytes] = None

    @property
    def salt_path(self) -> Path:
        return self.paths.home / "key.salt"

    def available(self) -> bool:
        return True

    def exists(self) -> bool:
        return self.salt_path.exists()

    def _ask(self, label: str) -> str:
        if self._prompt is not None:
            return self._prompt(label)
        import getpass

        return getpass.getpass(label)

    @classmethod
    def derive(cls, passphrase: str, salt: bytes) -> bytes:
        return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=cls.SCRYPT_N,
                              r=cls.SCRYPT_R, p=cls.SCRYPT_P, dklen=32,
                              maxmem=256 * 1024 * 1024)

    def create(self) -> bytes:
        first = self._ask("New passphrase: ")
        if len(first) < 8:
            raise KeyProviderError("passphrase must be at least 8 characters")
        if first != self._ask("Confirm passphrase: "):
            raise KeyProviderError("passphrases did not match")
        salt = os.urandom(16)
        self.paths.home.mkdir(parents=True, exist_ok=True)
        self.salt_path.write_bytes(salt)
        self._cached = self.derive(first, salt)
        return self._cached

    def load(self) -> bytes:
        if self._cached is not None:
            return self._cached
        if not self.salt_path.exists():
            raise KeyProviderError(f"no salt file at {self.salt_path}")
        salt = self.salt_path.read_bytes()
        self._cached = self.derive(self._ask("Passphrase: "), salt)
        return self._cached

    def destroy(self) -> None:
        self._cached = None
        with contextlib.suppress(OSError):
            self.salt_path.unlink()

    def verify(self) -> bool:
        # The passphrase cannot be re-derived without asking again, and a wrong
        # passphrase is only detectable against the database itself. Creation
        # already required typing it twice.
        return self._cached is not None and len(self._cached) == 32


class FileKeyProvider(KeyProvider):
    """The key in a mode-0600 file beside the database. The weakest option, and
    labelled as such: it protects a copied database file and nothing else."""

    name = "file"
    description = "key file next to the database (weak: protects backups only)"
    unattended = True

    @property
    def key_path(self) -> Path:
        return self.paths.home / "key.bin"

    def available(self) -> bool:
        return True

    def exists(self) -> bool:
        return self.key_path.exists()

    def create(self) -> bytes:
        key = os.urandom(32)
        self.paths.home.mkdir(parents=True, exist_ok=True)
        self.key_path.write_bytes(key)
        if not IS_WINDOWS:
            with contextlib.suppress(OSError):
                os.chmod(self.key_path, 0o600)
        return key

    def load(self) -> bytes:
        if not self.key_path.exists():
            raise KeyProviderError(f"no key file at {self.key_path}")
        key = self.key_path.read_bytes()
        if len(key) != 32:
            raise KeyProviderError(f"key file {self.key_path} is corrupt")
        return key

    def destroy(self) -> None:
        with contextlib.suppress(OSError):
            self.key_path.unlink()


PROVIDER_CLASSES: Dict[str, type] = {
    "dpapi": DPAPIKeyProvider,
    "keychain": KeychainKeyProvider,
    "passphrase": PassphraseKeyProvider,
    "file": FileKeyProvider,
}


def make_provider(name: str, paths: "Paths",
                  prompt: Optional[Callable[[str], str]] = None) -> KeyProvider:
    cls = PROVIDER_CLASSES.get(name)
    if cls is None:
        raise KeyProviderError(f"unknown key provider {name!r}")
    if cls is PassphraseKeyProvider:
        return cls(paths, prompt)  # type: ignore[call-arg]
    return cls(paths)


def default_provider_name() -> str:
    """The best unattended option this platform offers."""
    if IS_WINDOWS:
        return "dpapi"
    if IS_MACOS:
        return "keychain"
    return "file"


# ==========================================================================
# Encryption state + key resolution
# ==========================================================================

_KEY_CACHE: Dict[str, bytes] = {}
_KEY_LOCK = threading.Lock()


def state_path(home: Path) -> Path:
    return home / "encryption.json"


def encryption_state(home: Path) -> Dict[str, Any]:
    """What the on-disk marker says. Never raises."""
    path = state_path(home)
    if not path.exists():
        return {"enabled": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"enabled": False}
    except (OSError, ValueError):
        return {"enabled": False}


def write_encryption_state(home: Path, state: Dict[str, Any]) -> None:
    home.mkdir(parents=True, exist_ok=True)
    state_path(home).write_text(json.dumps(state, indent=2), encoding="utf-8")


def is_encrypted(home: Path) -> bool:
    return bool(encryption_state(home).get("enabled"))


def database_looks_encrypted(path: Path) -> Optional[bool]:
    """Inspect the actual file, not the marker. None when it cannot be read.

    Every plain SQLite database begins with the ASCII bytes "SQLite format 3".
    SQLCipher encrypts from byte zero, so that header is simply not there. This
    is the check that does not take the tool's own word for it.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(16)
    except OSError:
        return None
    if not head:
        return None
    return not head.startswith(b"SQLite format 3")


def cache_key(home: Path, key: bytes) -> None:
    with _KEY_LOCK:
        _KEY_CACHE[str(home)] = key


def forget_cached_key(home: Path) -> None:
    with _KEY_LOCK:
        _KEY_CACHE.pop(str(home), None)


def active_key(home: Path, prompt: Optional[Callable[[str], str]] = None) -> Optional[bytes]:
    """The key for this database, or None when encryption is off.

    Cached per process so a passphrase is typed once, not once per Store.
    """
    state = encryption_state(home)
    if not state.get("enabled"):
        return None
    with _KEY_LOCK:
        cached = _KEY_CACHE.get(str(home))
    if cached is not None:
        return cached
    provider = make_provider(str(state.get("provider", "file")), Paths(home), prompt)
    key = provider.load()
    cache_key(home, key)
    return key


def open_database(path: Path, key: Optional[bytes] = None, timeout: float = 15.0):
    """Open a database connection, encrypted when a key is supplied."""
    if key is None:
        conn = sqlite3.connect(str(path), timeout=timeout, isolation_level=None,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    if _sqlcipher is None:
        raise MindError(SQLCIPHER_MISSING)
    conn = _sqlcipher.connect(str(path), timeout=timeout, isolation_level=None,
                              check_same_thread=False)
    conn.row_factory = _sqlcipher.Row
    # The key PRAGMA must be the very first statement on the connection.
    conn.execute(_hex_key_pragma(key))
    return conn


# ==========================================================================
# Turning encryption on and off
# ==========================================================================

FILE_LOCKED_HELP = (
    "another process still has the database open, so it cannot be replaced.\n"
    "    Windows will not rename a file while anything holds a handle to it.\n"
    f"    NOTE: `{APP_NAME} pause` is not enough — a paused daemon is still\n"
    "    running and still holds the file. The process has to actually exit.\n"
    "\n"
    f"    1. End the capture process: Task Manager > Details > python.exe or\n"
    "       pythonw.exe (the one running it), End task. A reboot also works.\n"
    f"    2. Close any other {APP_NAME} chat/ask window.\n"
    f"    3. Run it again: {APP_NAME} encrypt on\n"
    f"    (To stop it coming back at logon first: {APP_NAME} uninstall)\n"
    "\n"
    "    Your database was NOT changed.")


def _replace_with_retry(source: Path, target: Path, attempts: int = 6) -> None:
    """os.replace, retried briefly.

    POSIX renames over open files happily; Windows raises WinError 32 while any
    handle is open — including a virus scanner that opened the file a moment
    ago. A few short retries clear the transient cases; a genuinely running
    daemon still fails, and the caller turns that into an instruction.
    """
    last: Optional[OSError] = None
    for attempt in range(attempts):
        try:
            os.replace(str(source), str(target))
            return
        except PermissionError as exc:  # WinError 32
            last = exc
            time.sleep(0.3 * (attempt + 1))
        except OSError as exc:
            raise exc
    raise last if last is not None else OSError("replace failed")


def _swap_into_place(live: Path, replacement: Path, backup: Path) -> None:
    """Move `replacement` into `live`, keeping the old `live` as `backup`.

    If the second move fails the first is undone, so the process can never end
    with no database at all — the outcome that would actually lose data.
    """
    try:
        _replace_with_retry(live, backup)
    except OSError as exc:
        raise MindError(FILE_LOCKED_HELP) from exc
    try:
        _replace_with_retry(replacement, live)
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.replace(str(backup), str(live))  # put the original back
        raise MindError(FILE_LOCKED_HELP) from exc


def _row_census(conn) -> Dict[str, int]:
    """Row counts per real table — the check that migration lost nothing."""
    census: Dict[str, int] = {}
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%'").fetchall()
    for row in tables:
        name = row[0]
        with contextlib.suppress(Exception):
            census[name] = conn.execute(f"SELECT count(*) FROM \"{name}\"").fetchone()[0]
    return census


def encrypt_database(paths: "Paths", provider: KeyProvider,
                     progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Encrypt the database in place, verifying before anything is destroyed.

    Order matters and is deliberate: the key must round-trip, the encrypted
    copy must open and match the original row for row, and the plaintext
    original is kept as a backup. Only then does the new file take its place.
    """
    def say(message: str) -> None:
        if progress:
            progress(message)

    if _sqlcipher is None:
        raise MindError(SQLCIPHER_MISSING)
    if is_encrypted(paths.home):
        raise MindError("this database is already encrypted")

    say("generating key")
    key = provider.create()
    if len(key) != 32:
        raise KeyProviderError("provider returned a key of the wrong size")

    # Prove we can read the key back BEFORE encrypting anything with it.
    say(f"verifying the {provider.name} key can be read back")
    if not provider.verify():
        provider.destroy()
        raise KeyProviderError(
            f"the {provider.name} key could not be read back after storing it — "
            "refusing to encrypt, your data is untouched")

    encrypted = Path(str(paths.db) + ".encrypting")
    backup = Path(str(paths.db) + ".plaintext-backup")
    for stale in (encrypted,):
        with contextlib.suppress(OSError):
            stale.unlink()

    if not paths.db.exists():
        # Nothing to migrate: just record the state and let Store create it.
        say("no existing database — new one will be created encrypted")
        write_encryption_state(paths.home, {
            "enabled": True, "provider": provider.name, "cipher": "sqlcipher4",
            "created_at": now_ts()})
        cache_key(paths.home, key)
        return {"rows": 0, "provider": provider.name, "backup": None}

    say("copying into an encrypted database")
    source = _sqlcipher.connect(str(paths.db), isolation_level=None)
    try:
        before = _row_census(source)
        source.execute("ATTACH DATABASE ? AS encrypted KEY \"x'" + key.hex() + "'\"",
                       (str(encrypted),))
        source.execute("SELECT sqlcipher_export('encrypted')")
        source.execute("DETACH DATABASE encrypted")
    finally:
        with contextlib.suppress(Exception):
            source.close()

    say("verifying every row survived")
    check = open_database(encrypted, key)
    try:
        after = _row_census(check)
    finally:
        with contextlib.suppress(Exception):
            check.close()
    missing = {name: (count, after.get(name)) for name, count in before.items()
               if after.get(name) != count}
    if missing:
        with contextlib.suppress(OSError):
            encrypted.unlink()
        provider.destroy()
        raise MindError(
            "encrypted copy did not match the original "
            f"({missing}) — aborted, your database is untouched")

    say("swapping files (plaintext kept as a backup)")
    with contextlib.suppress(OSError):
        backup.unlink()
    try:
        _swap_into_place(paths.db, encrypted, backup)
    except MindError:
        # Leave nothing half-done: drop the temp copy and the unused key so a
        # retry starts clean, and let the caller show the instructions.
        with contextlib.suppress(OSError):
            encrypted.unlink()
        with contextlib.suppress(Exception):
            provider.destroy()
        raise
    # WAL/SHM belong to the old plaintext file; SQLite recreates them.
    for suffix in ("-wal", "-shm"):
        with contextlib.suppress(OSError):
            Path(str(backup) + suffix).unlink()

    write_encryption_state(paths.home, {
        "enabled": True, "provider": provider.name, "cipher": "sqlcipher4",
        "created_at": now_ts()})
    cache_key(paths.home, key)
    return {"rows": sum(before.values()), "provider": provider.name,
            "backup": str(backup)}


def decrypt_database(paths: "Paths",
                     prompt: Optional[Callable[[str], str]] = None,
                     progress: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Turn encryption off, writing a plaintext database back in place."""
    def say(message: str) -> None:
        if progress:
            progress(message)

    state = encryption_state(paths.home)
    if not state.get("enabled"):
        raise MindError("this database is not encrypted")
    if _sqlcipher is None:
        raise MindError(SQLCIPHER_MISSING)

    key = active_key(paths.home, prompt)
    if key is None:
        raise MindError("could not load the encryption key")

    plain = Path(str(paths.db) + ".decrypting")
    with contextlib.suppress(OSError):
        plain.unlink()

    say("copying into a plaintext database")
    source = open_database(paths.db, key)
    try:
        before = _row_census(source)
        source.execute("ATTACH DATABASE ? AS plaintext KEY ''", (str(plain),))
        source.execute("SELECT sqlcipher_export('plaintext')")
        source.execute("DETACH DATABASE plaintext")
    finally:
        with contextlib.suppress(Exception):
            source.close()

    say("verifying every row survived")
    check = open_database(plain, None)
    try:
        after = _row_census(check)
    finally:
        with contextlib.suppress(Exception):
            check.close()
    if any(after.get(name) != count for name, count in before.items()):
        with contextlib.suppress(OSError):
            plain.unlink()
        raise MindError("decrypted copy did not match — aborted, nothing changed")

    encrypted_backup = Path(str(paths.db) + ".encrypted-backup")
    with contextlib.suppress(OSError):
        encrypted_backup.unlink()
    try:
        _swap_into_place(paths.db, plain, encrypted_backup)
    except MindError:
        with contextlib.suppress(OSError):
            plain.unlink()
        raise
    with contextlib.suppress(OSError):
        encrypted_backup.unlink()
    for suffix in ("-wal", "-shm"):
        with contextlib.suppress(OSError):
            Path(str(paths.db) + suffix).unlink()

    provider = make_provider(str(state.get("provider", "file")), paths, prompt)
    provider.destroy()
    write_encryption_state(paths.home, {"enabled": False})
    forget_cached_key(paths.home)
    return {"rows": sum(before.values())}


# ==========================================================================
# Full-disk encryption detection
# ==========================================================================

def disk_encryption_status() -> Tuple[Optional[bool], str]:
    """(enabled, human description). None means "could not determine".

    Full-disk encryption is the defence that actually matters for a stolen
    machine, and it costs no code — so the least this tool can do is tell you
    whether it is on.
    """
    try:
        if IS_MACOS:
            result = subprocess.run(["fdesetup", "status"], capture_output=True,
                                    text=True, timeout=10)
            text = (result.stdout or "").strip()
            if "FileVault is On" in text:
                return True, "FileVault is on"
            if "FileVault is Off" in text:
                return False, "FileVault is OFF"
            return None, text[:80] or "could not read FileVault status"

        if IS_WINDOWS:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-BitLockerVolume -MountPoint $env:SystemDrive)"
                 ".ProtectionStatus"],
                capture_output=True, text=True, timeout=25)
            text = (result.stdout or "").strip()
            if text.startswith("On") or text == "1":
                return True, "BitLocker is on for the system drive"
            if text.startswith("Off") or text == "0":
                return False, "BitLocker is OFF for the system drive"
            return None, "could not read BitLocker status (needs an elevated shell?)"

        result = subprocess.run(["lsblk", "-o", "TYPE", "-n"], capture_output=True,
                                text=True, timeout=10)
        if "crypt" in (result.stdout or ""):
            return True, "a LUKS/dm-crypt volume is present"
        return False, "no dm-crypt volume found"
    except (OSError, subprocess.SubprocessError):
        return None, "could not determine disk encryption status"


# ==========================================================================
# Ollama client
# ==========================================================================

@dataclass
class ModelInfo:
    name: str
    size: int = 0


class OllamaClient:
    """Small, dependency-free Ollama client with pooling and retries."""

    def __init__(self, base_url: str, timeout: float = 120.0, chat_timeout: float = 600.0,
                 retries: int = 3) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https"):
            raise ConfigError(f"invalid ollama_url: {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.https = parsed.scheme == "https"
        self.timeout = timeout
        self.chat_timeout = chat_timeout
        self.retries = max(1, retries)
        self._pool: List[http.client.HTTPConnection] = []
        self._lock = threading.Lock()
        self._embed_endpoint: Optional[str] = None  # discovered: /api/embed or /api/embeddings

    # -- connection handling ----------------------------------------------
    def _new_conn(self, timeout: float) -> http.client.HTTPConnection:
        if self.https:
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def _acquire(self, timeout: float) -> http.client.HTTPConnection:
        with self._lock:
            while self._pool:
                conn = self._pool.pop()
                conn.timeout = timeout
                if conn.sock is not None:
                    return conn
        return self._new_conn(timeout)

    def _release(self, conn: http.client.HTTPConnection) -> None:
        with self._lock:
            if len(self._pool) < 4:
                self._pool.append(conn)
                return
        with contextlib.suppress(Exception):
            conn.close()

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, []
        for conn in pool:
            with contextlib.suppress(Exception):
                conn.close()

    # -- requests ----------------------------------------------------------
    def _request(self, method: str, path: str, payload: Optional[dict] = None,
                 timeout: Optional[float] = None) -> Tuple[int, bytes]:
        timeout = timeout or self.timeout
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"

        last_exc: Optional[Exception] = None
        for attempt in range(self.retries):
            conn = self._acquire(timeout)
            try:
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                data = response.read()
                status = response.status
                if response.getheader("Connection", "").lower() == "close":
                    with contextlib.suppress(Exception):
                        conn.close()
                else:
                    self._release(conn)
                return status, data
            except (http.client.HTTPException, OSError) as exc:
                last_exc = exc
                with contextlib.suppress(Exception):
                    conn.close()
                if attempt + 1 < self.retries:
                    time.sleep(min(2.0 ** attempt * 0.25, 4.0))
        raise OllamaError(f"{method} {path} failed after {self.retries} attempts: {last_exc}")

    def _request_stream(self, method: str, path: str, payload: dict,
                        timeout: Optional[float] = None) -> Iterator[dict]:
        """Yield decoded NDJSON objects from a streaming endpoint."""
        timeout = timeout or self.chat_timeout
        body = json.dumps(payload).encode("utf-8")
        conn = self._new_conn(timeout)
        try:
            conn.request(method, path, body=body,
                         headers={"Content-Type": "application/json", "Accept": "application/x-ndjson"})
            response = conn.getresponse()
            if response.status >= 400:
                detail = response.read().decode("utf-8", "replace")[:400]
                raise OllamaError(f"{path} returned HTTP {response.status}: {detail}")
            for raw_line in response:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line.decode("utf-8", "replace"))
                except ValueError:
                    continue
        except (http.client.HTTPException, OSError) as exc:
            raise OllamaError(f"streaming {path} failed: {exc}") from exc
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def _json(self, method: str, path: str, payload: Optional[dict] = None,
              timeout: Optional[float] = None) -> dict:
        status, data = self._request(method, path, payload, timeout)
        if status >= 400:
            raise OllamaError(f"{path} returned HTTP {status}: {data[:300].decode('utf-8', 'replace')}")
        try:
            return json.loads(data.decode("utf-8", "replace"))
        except ValueError as exc:
            raise OllamaError(f"{path} returned invalid JSON") from exc

    # -- API ---------------------------------------------------------------
    def is_up(self) -> bool:
        try:
            self._request("GET", "/api/tags", timeout=5)
            return True
        except OllamaError:
            return False

    def list_models(self) -> List[ModelInfo]:
        data = self._json("GET", "/api/tags", timeout=15)
        models = []
        for entry in data.get("models", []):
            name = entry.get("name") or entry.get("model") or ""
            if name:
                models.append(ModelInfo(name=name, size=int(entry.get("size", 0) or 0)))
        return models

    def has_model(self, name: str) -> bool:
        if not name:
            return False
        try:
            available = {m.name for m in self.list_models()}
        except OllamaError:
            return False
        if name in available:
            return True
        # `llama3.2` should match `llama3.2:latest` and vice versa.
        base = name.split(":")[0]
        return any(m.split(":")[0] == base for m in available)

    def pull(self, model: str) -> Iterator[str]:
        """Stream progress lines while pulling a model."""
        for chunk in self._request_stream("POST", "/api/pull", {"model": model, "stream": True},
                                          timeout=3600):
            if "error" in chunk:
                raise OllamaError(str(chunk["error"]))
            status = chunk.get("status", "")
            completed, total = chunk.get("completed"), chunk.get("total")
            if completed and total:
                pct = 100.0 * float(completed) / float(total)
                yield f"{status} {pct:.0f}%"
            elif status:
                yield status

    def embed(self, texts: Sequence[str], model: str) -> List[List[float]]:
        """Embed a batch. Uses /api/embed when available, else /api/embeddings."""
        if not texts:
            return []
        if self._embed_endpoint in (None, "/api/embed"):
            try:
                data = self._json("POST", "/api/embed", {"model": model, "input": list(texts)})
                vectors = data.get("embeddings")
                if isinstance(vectors, list) and len(vectors) == len(texts):
                    self._embed_endpoint = "/api/embed"
                    return [[float(x) for x in vec] for vec in vectors]
            except OllamaError:
                # Older servers only expose /api/embeddings (single input).
                if self._embed_endpoint == "/api/embed":
                    raise
        out: List[List[float]] = []
        for text in texts:
            data = self._json("POST", "/api/embeddings", {"model": model, "prompt": text})
            vector = data.get("embedding")
            if not isinstance(vector, list) or not vector:
                raise OllamaError(f"embedding model {model!r} returned no vector")
            out.append([float(x) for x in vector])
        self._embed_endpoint = "/api/embeddings"
        return out

    def embed_one(self, text: str, model: str) -> List[float]:
        return self.embed([text], model)[0]

    def chat_stream(self, model: str, messages: List[dict],
                    options: Optional[dict] = None) -> Iterator[str]:
        payload = {"model": model, "messages": messages, "stream": True}
        if options:
            payload["options"] = options
        for chunk in self._request_stream("POST", "/api/chat", payload):
            if "error" in chunk:
                raise OllamaError(str(chunk["error"]))
            piece = (chunk.get("message") or {}).get("content", "")
            if piece:
                yield piece
            if chunk.get("done"):
                break

    def chat(self, model: str, messages: List[dict], options: Optional[dict] = None) -> str:
        return "".join(self.chat_stream(model, messages, options))

    def chat_with_tools(self, model: str, messages: List[dict], tools: List[dict],
                        options: Optional[dict] = None) -> dict:
        """One non-streaming turn that may return tool calls.

        Streaming and tool calls do not mix cleanly, so the agent loop runs
        unstreamed and only the final answer is shown.
        """
        payload: Dict[str, Any] = {"model": model, "messages": messages,
                                   "tools": tools, "stream": False}
        if options:
            payload["options"] = options
        data = self._json("POST", "/api/chat", payload, timeout=self.chat_timeout)
        message = data.get("message")
        if not isinstance(message, dict):
            raise OllamaError("chat response had no message")
        return message

    def chat_with_tools_stream(self, model: str, messages: List[dict], tools: List[dict],
                               options: Optional[dict] = None) -> Iterator[Tuple[str, Any]]:
        """Streaming tool-calling turn.

        Yields ("text", chunk) as answer tokens arrive and ("done", {content,
        tool_calls}) at the end. Tool-call turns usually stream no text — the
        model returns the calls in one chunk — so the caller shows a spinner
        until it sees whether this turn is tools or a final answer.
        """
        payload: Dict[str, Any] = {"model": model, "messages": messages,
                                   "tools": tools, "stream": True}
        if options:
            payload["options"] = options
        content_parts: List[str] = []
        tool_calls: List[dict] = []
        for chunk in self._request_stream("POST", "/api/chat", payload):
            if "error" in chunk:
                raise OllamaError(str(chunk["error"]))
            message = chunk.get("message") or {}
            piece = message.get("content", "")
            if piece:
                content_parts.append(piece)
                yield ("text", piece)
            calls = message.get("tool_calls")
            if calls:
                tool_calls.extend(calls)
            if chunk.get("done"):
                break
        yield ("done", {"content": "".join(content_parts), "tool_calls": tool_calls})

    def supports_tools(self, model: str) -> bool:
        """Probe once with a trivial tool. Models without tool support error out."""
        probe = [{"type": "function", "function": {
            "name": "noop", "description": "does nothing",
            "parameters": {"type": "object", "properties": {}}}}]
        try:
            self.chat_with_tools(model, [{"role": "user", "content": "say ok"}], probe,
                                 {"num_ctx": 2048})
            return True
        except OllamaError:
            return False


# ==========================================================================
# Vector encoding
# ==========================================================================

def normalize_vector(vec: Sequence[float]) -> List[float]:
    norm = math.sqrt(sum(float(v) * float(v) for v in vec))
    if norm == 0.0:
        return [0.0] * len(vec)
    return [float(v) / norm for v in vec]


def pack_vector(vec: Sequence[float]) -> Tuple[bytes, bytes, int]:
    """Return (float32 little-endian blob, sign-bit blob, dim) for a normalized vector."""
    unit = normalize_vector(vec)
    dim = len(unit)
    blob = struct.pack(f"<{dim}f", *unit)
    bits = bytearray((dim + 7) // 8)
    for i, value in enumerate(unit):
        if value > 0:
            bits[i >> 3] |= 0x80 >> (i & 7)
    return blob, bytes(bits), dim


def unpack_vector(blob: bytes) -> List[float]:
    dim = len(blob) // 4
    return list(struct.unpack(f"<{dim}f", blob))


def hamming(a: int, b: int) -> int:
    x = a ^ b
    try:
        return x.bit_count()  # Python 3.10+
    except AttributeError:  # pragma: no cover - older interpreters
        return bin(x).count("1")


# ==========================================================================
# Storage
# ==========================================================================

@dataclass
class CaptureRow:
    id: int
    ts: float
    source: str
    origin: str
    text: str
    meta: Dict[str, Any] = field(default_factory=dict)


class Store:
    """SQLite persistence. One instance per thread that touches the DB."""

    def __init__(self, path: Path, read_only: bool = False,
                 key: Optional[bytes] = None) -> None:
        self.path = path
        self.read_only = read_only
        path.parent.mkdir(parents=True, exist_ok=True)
        # Encryption is transparent to every caller: if this home is marked
        # encrypted, the key is resolved (and cached per process) here rather
        # than threaded through dozens of Store(...) call sites.
        if key is None:
            key = active_key(path.parent)
        self.key = key
        self.encrypted = key is not None
        self.conn = open_database(path, key)
        self._configure()
        self.has_fts = self._detect_fts()
        if not read_only:
            self._migrate()
            if not IS_WINDOWS:
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o600)

    # -- setup -------------------------------------------------------------
    def _configure(self) -> None:
        cur = self.conn
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.execute("PRAGMA temp_store=MEMORY")
        cur.execute("PRAGMA cache_size=-40000")  # ~40MB page cache
        with contextlib.suppress(DB_ERRORS):
            cur.execute("PRAGMA mmap_size=268435456")

    def _detect_fts(self) -> bool:
        try:
            self.conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_probe USING fts5(x)")
            self.conn.execute("DROP TABLE IF EXISTS _fts_probe")
            return True
        except DB_ERRORS:
            return False

    def _migrate(self) -> None:
        c = self.conn
        c.execute("BEGIN")
        try:
            c.execute("""CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
            c.execute("""CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                source TEXT NOT NULL,
                origin TEXT NOT NULL DEFAULT '',
                text TEXT NOT NULL,
                meta TEXT NOT NULL DEFAULT '{}',
                hash TEXT NOT NULL,
                dim INTEGER,
                embedding BLOB,
                bits BLOB)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_captures_ts ON captures(ts)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_captures_hash ON captures(hash, ts)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_captures_source ON captures(source, ts)")
            # Researched facts live apart from personal captures: different
            # lifetime, different privacy weight, and `forget --all` on your
            # own history must not silently wipe a cache of public facts (or
            # the reverse).
            c.execute("""CREATE TABLE IF NOT EXISTS knowledge (
                key TEXT PRIMARY KEY,
                query TEXT NOT NULL,
                answer TEXT NOT NULL,
                sources TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL DEFAULT 'default',
                fetched_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                hits INTEGER NOT NULL DEFAULT 0)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_expiry ON knowledge(expires_at)")
            # Durable, generalized facts about the user, distilled from captures
            # by the nightly reflection pass. Separate from episodes: this is
            # semantic memory, editable and deletable line by line, and every
            # row records the activity window it was inferred from.
            c.execute("""CREATE TABLE IF NOT EXISTS profile (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                norm TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL DEFAULT 'general',
                evidence TEXT NOT NULL DEFAULT '{}',
                source TEXT NOT NULL DEFAULT 'inferred',
                confidence REAL NOT NULL DEFAULT 1.0,
                dim INTEGER,
                embedding BLOB,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_profile_conf ON profile(confidence DESC)")
            c.execute("""CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                mtime REAL NOT NULL,
                size INTEGER NOT NULL,
                hash TEXT NOT NULL,
                indexed_at REAL NOT NULL)""")
            c.execute("""CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at REAL NOT NULL,
                title TEXT NOT NULL DEFAULT '')""")
            c.execute("""CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                ts REAL NOT NULL)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, id)")
            if self.has_fts:
                c.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS captures_fts USING fts5(
                    text, content='captures', content_rowid='id', tokenize='unicode61')""")
                c.execute("""CREATE TRIGGER IF NOT EXISTS captures_ai AFTER INSERT ON captures BEGIN
                    INSERT INTO captures_fts(rowid, text) VALUES (new.id, new.text);
                END""")
                c.execute("""CREATE TRIGGER IF NOT EXISTS captures_ad AFTER DELETE ON captures BEGIN
                    INSERT INTO captures_fts(captures_fts, rowid, text)
                    VALUES ('delete', old.id, old.text);
                END""")
                c.execute("""CREATE TRIGGER IF NOT EXISTS captures_au
                    AFTER UPDATE OF text ON captures BEGIN
                    INSERT INTO captures_fts(captures_fts, rowid, text)
                    VALUES ('delete', old.id, old.text);
                    INSERT INTO captures_fts(rowid, text) VALUES (new.id, new.text);
                END""")
            c.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)",
                      (str(SCHEMA_VERSION),))
            c.execute("COMMIT")
        except DB_ERRORS:
            c.execute("ROLLBACK")
            raise

    # -- meta --------------------------------------------------------------
    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # -- writes ------------------------------------------------------------
    def insert_batch(self, items: Sequence[dict]) -> int:
        """Insert captures. Each item: ts, source, origin, text, meta, vector(optional)."""
        if not items:
            return 0
        rows = []
        for item in items:
            text = item["text"]
            vector = item.get("vector")
            if vector:
                blob, bits, dim = pack_vector(vector)
            else:
                blob, bits, dim = None, None, None
            rows.append((
                float(item.get("ts", now_ts())),
                str(item.get("source", "unknown")),
                str(item.get("origin", "")),
                text,
                json.dumps(item.get("meta", {}), ensure_ascii=False),
                item.get("hash") or sha256_hex(text),
                dim, blob, bits,
            ))
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.executemany(
                "INSERT INTO captures (ts, source, origin, text, meta, hash, dim, embedding, bits) "
                "VALUES (?,?,?,?,?,?,?,?,?)", rows)
            self.conn.execute("COMMIT")
        except DB_ERRORS:
            self.conn.execute("ROLLBACK")
            raise
        return len(rows)

    def seen_recently(self, text_hash: str, source: str, within_sec: float) -> bool:
        cutoff = now_ts() - within_sec
        row = self.conn.execute(
            "SELECT 1 FROM captures WHERE hash=? AND source=? AND ts >= ? LIMIT 1",
            (text_hash, source, cutoff)).fetchone()
        return row is not None

    def pending_embeddings(self, limit: int = 64) -> List[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT id, text FROM captures WHERE embedding IS NULL ORDER BY id LIMIT ?", (limit,)))

    def count_pending(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM captures WHERE embedding IS NULL").fetchone()["n"]

    def set_embeddings(self, pairs: Sequence[Tuple[int, Sequence[float]]]) -> None:
        if not pairs:
            return
        rows = []
        for row_id, vector in pairs:
            blob, bits, dim = pack_vector(vector)
            rows.append((blob, bits, dim, row_id))
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.executemany(
                "UPDATE captures SET embedding=?, bits=?, dim=? WHERE id=?", rows)
            self.conn.execute("COMMIT")
        except DB_ERRORS:
            self.conn.execute("ROLLBACK")
            raise

    def clear_embeddings(self) -> int:
        cur = self.conn.execute("UPDATE captures SET embedding=NULL, bits=NULL, dim=NULL")
        return cur.rowcount

    def prune(self, retention_days: int, max_entries: int = 0) -> int:
        cutoff = now_ts() - retention_days * 86400
        removed = self.conn.execute("DELETE FROM captures WHERE ts < ?", (cutoff,)).rowcount or 0
        if max_entries and max_entries > 0:
            total = self.count()
            excess = total - max_entries
            if excess > 0:
                removed += self.conn.execute(
                    "DELETE FROM captures WHERE id IN "
                    "(SELECT id FROM captures ORDER BY ts ASC LIMIT ?)", (excess,)).rowcount or 0
        return removed

    def delete_all(self) -> int:
        removed = self.conn.execute("DELETE FROM captures").rowcount or 0
        self.conn.execute("DELETE FROM files")
        return removed

    def delete_source(self, source: str) -> int:
        return self.conn.execute("DELETE FROM captures WHERE source=?", (source,)).rowcount or 0

    def delete_matching(self, needle: str) -> int:
        return self.conn.execute(
            "DELETE FROM captures WHERE text LIKE ?", (f"%{needle}%",)).rowcount or 0

    def vacuum(self) -> None:
        with contextlib.suppress(DB_ERRORS):
            self.conn.execute("VACUUM")

    def integrity_ok(self) -> bool:
        row = self.conn.execute("PRAGMA quick_check").fetchone()
        return bool(row) and str(row[0]).lower() == "ok"

    # -- file index --------------------------------------------------------
    def file_state(self, path: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM files WHERE path=?", (path,)).fetchone()

    def upsert_file(self, path: str, mtime: float, size: int, file_hash: str) -> None:
        self.conn.execute(
            "INSERT INTO files(path, mtime, size, hash, indexed_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime, size=excluded.size, "
            "hash=excluded.hash, indexed_at=excluded.indexed_at",
            (path, mtime, size, file_hash, now_ts()))

    def delete_file_chunks(self, path: str) -> int:
        return self.conn.execute(
            "DELETE FROM captures WHERE source='file' AND origin=?", (path,)).rowcount or 0

    def known_files(self) -> List[str]:
        return [r["path"] for r in self.conn.execute("SELECT path FROM files")]

    def forget_file(self, path: str) -> None:
        self.conn.execute("DELETE FROM files WHERE path=?", (path,))

    # -- reads -------------------------------------------------------------
    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM captures").fetchone()["n"]

    def stats(self) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS total, MIN(ts) AS oldest, MAX(ts) AS newest FROM captures").fetchone()
        by_source = {r["source"]: r["n"] for r in self.conn.execute(
            "SELECT source, COUNT(*) AS n FROM captures GROUP BY source ORDER BY n DESC")}
        db_bytes = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                db_bytes += candidate.stat().st_size
        return {
            "total": row["total"] or 0,
            "oldest": row["oldest"],
            "newest": row["newest"],
            "by_source": by_source,
            "pending": self.count_pending(),
            "db_bytes": db_bytes,
            "fts": self.has_fts,
        }

    def recent(self, limit: int = 20, source: Optional[str] = None) -> List[sqlite3.Row]:
        if source:
            return list(self.conn.execute(
                "SELECT * FROM captures WHERE source=? ORDER BY ts DESC LIMIT ?", (source, limit)))
        return list(self.conn.execute("SELECT * FROM captures ORDER BY ts DESC LIMIT ?", (limit,)))

    def in_range(self, start: float, end: float, limit: int = 40,
                 sources: Optional[Sequence[str]] = None) -> List[sqlite3.Row]:
        """Everything captured in a window, oldest first.

        This is what a question like 'what was I watching at 5pm' actually
        needs: a range scan, not a similarity search.
        """
        sql = "SELECT * FROM captures WHERE ts >= ? AND ts <= ?"
        params: List[Any] = [float(start), float(end)]
        if sources:
            sql += " AND source IN (" + ",".join("?" * len(sources)) + ")"
            params.extend(sources)
        sql += " ORDER BY ts ASC LIMIT ?"
        params.append(int(limit))
        return list(self.conn.execute(sql, tuple(params)))

    def app_usage(self, start: float, end: float, limit: int = 40) -> List[Dict[str, Any]]:
        """Aggregate focus sessions per app in a window.

        Focus rows already carry duration_sec in meta; this rolls them up so
        "what did I spend time in" and "how long was I in <app>" are one query,
        not a scan the model has to sum in its head.
        """
        rows = self.conn.execute(
            "SELECT origin, meta, ts FROM captures WHERE source='focus' AND ts >= ? AND ts <= ?",
            (float(start), float(end)))
        agg: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            app = row["origin"] or "unknown"
            try:
                seconds = float(json.loads(row["meta"] or "{}").get("duration_sec", 0))
            except (TypeError, ValueError):
                seconds = 0.0
            entry = agg.setdefault(app, {"app": app, "seconds": 0.0, "sessions": 0,
                                         "first": row["ts"], "last": row["ts"]})
            entry["seconds"] += seconds
            entry["sessions"] += 1
            entry["first"] = min(entry["first"], row["ts"])
            entry["last"] = max(entry["last"], row["ts"])
        ranked = sorted(agg.values(), key=lambda e: e["seconds"], reverse=True)
        return ranked[:limit]

    def by_ids(self, ids: Sequence[int]) -> Dict[int, sqlite3.Row]:
        if not ids:
            return {}
        placeholders = ",".join("?" * len(ids))
        rows = self.conn.execute(
            f"SELECT * FROM captures WHERE id IN ({placeholders})", tuple(ids))
        return {row["id"]: row for row in rows}

    def dominant_dim(self) -> Optional[int]:
        row = self.conn.execute(
            "SELECT dim, COUNT(*) AS n FROM captures WHERE embedding IS NOT NULL AND dim IS NOT NULL "
            "GROUP BY dim ORDER BY n DESC LIMIT 1").fetchone()
        return row["dim"] if row else None

    def dim_histogram(self) -> Dict[int, int]:
        return {r["dim"]: r["n"] for r in self.conn.execute(
            "SELECT dim, COUNT(*) AS n FROM captures WHERE dim IS NOT NULL GROUP BY dim")}

    def iter_vectors(self, after_id: int = 0, dim: Optional[int] = None,
                     limit: Optional[int] = None) -> Iterator[sqlite3.Row]:
        sql = ("SELECT id, ts, dim, embedding, bits FROM captures "
               "WHERE embedding IS NOT NULL AND id > ?")
        params: List[Any] = [after_id]
        if dim is not None:
            sql += " AND dim = ?"
            params.append(dim)
        sql += " ORDER BY id"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return iter(self.conn.execute(sql, tuple(params)))

    def count_vectors(self, dim: Optional[int] = None) -> int:
        if dim is None:
            return self.conn.execute(
                "SELECT COUNT(*) AS n FROM captures WHERE embedding IS NOT NULL").fetchone()["n"]
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM captures WHERE embedding IS NOT NULL AND dim=?",
            (dim,)).fetchone()["n"]

    def keyword_search(self, query: str, limit: int = 50,
                       since_ts: Optional[float] = None) -> List[Tuple[int, float]]:
        """Return [(id, bm25_rank_score)] best-first."""
        tokens = [t for t in re.findall(r"[\w']+", query.lower()) if len(t) > 1][:24]
        if not tokens:
            return []
        if self.has_fts:
            match = " OR ".join(f'"{t}"' for t in tokens)
            sql = ("SELECT c.id AS id, bm25(captures_fts) AS score "
                   "FROM captures_fts JOIN captures c ON c.id = captures_fts.rowid "
                   "WHERE captures_fts MATCH ?")
            params: List[Any] = [match]
            if since_ts is not None:
                sql += " AND c.ts >= ?"
                params.append(since_ts)
            sql += " ORDER BY score LIMIT ?"
            params.append(limit)
            try:
                rows = self.conn.execute(sql, tuple(params)).fetchall()
                # bm25() returns lower-is-better; flip the sign for a positive score.
                return [(r["id"], -float(r["score"])) for r in rows]
            except DB_ERRORS:
                pass
        # Fallback: LIKE scan scored by number of matching tokens.
        clauses = " OR ".join("lower(text) LIKE ?" for _ in tokens)
        params = [f"%{t}%" for t in tokens]
        sql = f"SELECT id, text FROM captures WHERE ({clauses})"
        if since_ts is not None:
            sql += " AND ts >= ?"
            params.append(since_ts)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit * 4)
        scored: List[Tuple[int, float]] = []
        for row in self.conn.execute(sql, tuple(params)):
            lowered = row["text"].lower()
            scored.append((row["id"], float(sum(1 for t in tokens if t in lowered))))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:limit]

    # -- knowledge cache ---------------------------------------------------
    def knowledge_get(self, key: str) -> Optional[sqlite3.Row]:
        """Return a cache entry only if it has not expired."""
        row = self.conn.execute(
            "SELECT * FROM knowledge WHERE key=? AND expires_at > ?",
            (key, now_ts())).fetchone()
        if row is not None:
            self.conn.execute("UPDATE knowledge SET hits = hits + 1 WHERE key=?", (key,))
        return row

    def knowledge_put(self, key: str, query: str, answer: str, sources: str,
                      category: str, ttl_sec: float) -> None:
        now = now_ts()
        self.conn.execute(
            "INSERT INTO knowledge (key, query, answer, sources, category, fetched_at, "
            "expires_at, hits) VALUES (?,?,?,?,?,?,?,0) "
            "ON CONFLICT(key) DO UPDATE SET answer=excluded.answer, sources=excluded.sources, "
            "category=excluded.category, fetched_at=excluded.fetched_at, "
            "expires_at=excluded.expires_at",
            (key, query, answer, sources, category, now, now + ttl_sec))

    def knowledge_list(self, include_expired: bool = False) -> List[sqlite3.Row]:
        sql = "SELECT * FROM knowledge"
        if not include_expired:
            sql += f" WHERE expires_at > {now_ts()}"
        sql += " ORDER BY fetched_at DESC"
        return list(self.conn.execute(sql))

    def knowledge_prune(self) -> int:
        return self.conn.execute(
            "DELETE FROM knowledge WHERE expires_at <= ?", (now_ts(),)).rowcount or 0

    def knowledge_forget(self, needle: Optional[str] = None) -> int:
        if needle is None:
            return self.conn.execute("DELETE FROM knowledge").rowcount or 0
        return self.conn.execute(
            "DELETE FROM knowledge WHERE query LIKE ?", (f"%{needle}%",)).rowcount or 0

    def knowledge_stats(self) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS total, SUM(hits) AS hits FROM knowledge").fetchone()
        fresh = self.conn.execute(
            "SELECT COUNT(*) AS n FROM knowledge WHERE expires_at > ?", (now_ts(),)).fetchone()["n"]
        return {"total": row["total"] or 0, "fresh": fresh,
                "expired": (row["total"] or 0) - fresh, "hits": row["hits"] or 0}

    # -- profile (semantic memory) -----------------------------------------
    def profile_by_norm(self, norm: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM profile WHERE norm=?", (norm,)).fetchone()

    def profile_norms(self) -> List[Tuple[int, str]]:
        return [(r["id"], r["norm"]) for r in self.conn.execute("SELECT id, norm FROM profile")]

    def profile_insert(self, text: str, norm: str, category: str, evidence: dict,
                       source: str, confidence: float = 1.0,
                       vector: Optional[Sequence[float]] = None) -> int:
        now = now_ts()
        blob = dim = None
        if vector:
            blob, _bits, dim = pack_vector(vector)
        cur = self.conn.execute(
            "INSERT INTO profile (text, norm, category, evidence, source, confidence, "
            "dim, embedding, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (text, norm, category, json.dumps(evidence), source, confidence, dim, blob, now, now))
        return int(cur.lastrowid)

    def profile_reinforce(self, row_id: int, evidence: dict, category: str,
                          bump: float = 0.5) -> None:
        """A fact seen again: bump confidence, refresh recency, keep first-seen."""
        row = self.conn.execute("SELECT confidence FROM profile WHERE id=?", (row_id,)).fetchone()
        if row is None:
            return
        self.conn.execute(
            "UPDATE profile SET confidence=?, updated_at=?, evidence=?, category=? WHERE id=?",
            (min(float(row["confidence"]) + bump, 8.0), now_ts(), json.dumps(evidence),
             category, row_id))

    def profile_update_text(self, row_id: int, text: str, norm: str) -> None:
        self.conn.execute("UPDATE profile SET text=?, norm=?, updated_at=? WHERE id=?",
                          (text, norm, now_ts(), row_id))

    def profile_delete(self, row_id: int) -> None:
        self.conn.execute("DELETE FROM profile WHERE id=?", (row_id,))

    def profile_list(self, limit: int = 500) -> List[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM profile ORDER BY confidence DESC, updated_at DESC LIMIT ?", (limit,)))

    def profile_vectors(self) -> List[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT id, text, category, source, confidence, updated_at, dim, embedding "
            "FROM profile WHERE embedding IS NOT NULL"))

    def profile_forget(self, needle: Optional[str] = None) -> int:
        if needle is None:
            return self.conn.execute("DELETE FROM profile").rowcount or 0
        return self.conn.execute(
            "DELETE FROM profile WHERE text LIKE ?", (f"%{needle}%",)).rowcount or 0

    def profile_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM profile").fetchone()["n"]

    def captures_since(self, since_ts: float, limit: int = 200,
                       sources: Optional[Sequence[str]] = None) -> List[sqlite3.Row]:
        """Recent captures for the reflection pass, newest first."""
        sql = "SELECT id, ts, source, origin, text FROM captures WHERE ts > ?"
        params: List[Any] = [float(since_ts)]
        if sources:
            sql += " AND source IN (" + ",".join("?" * len(sources)) + ")"
            params.extend(sources)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))
        return list(self.conn.execute(sql, tuple(params)))

    # -- chat sessions -----------------------------------------------------
    def create_session(self, title: str = "") -> int:
        cur = self.conn.execute("INSERT INTO sessions(started_at, title) VALUES (?,?)",
                                (now_ts(), title))
        return int(cur.lastrowid)

    def latest_session(self) -> Optional[int]:
        row = self.conn.execute("SELECT id FROM sessions ORDER BY id DESC LIMIT 1").fetchone()
        return int(row["id"]) if row else None

    def add_message(self, session_id: int, role: str, content: str) -> None:
        self.conn.execute(
            "INSERT INTO messages(session_id, role, content, ts) VALUES (?,?,?,?)",
            (session_id, role, content, now_ts()))

    def session_messages(self, session_id: int, limit: int = 40) -> List[dict]:
        rows = self.conn.execute(
            "SELECT role, content FROM messages WHERE session_id=? ORDER BY id DESC LIMIT ?",
            (session_id, limit)).fetchall()
        return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]

    def export_rows(self, since_ts: Optional[float] = None) -> Iterator[sqlite3.Row]:
        if since_ts is None:
            return iter(self.conn.execute("SELECT * FROM captures ORDER BY ts"))
        return iter(self.conn.execute("SELECT * FROM captures WHERE ts >= ? ORDER BY ts", (since_ts,)))

    def close(self) -> None:
        with contextlib.suppress(DB_ERRORS):
            self.conn.close()


# ==========================================================================
# Vector index
# ==========================================================================

class VectorIndex:
    """In-memory similarity index over stored embeddings.

    Two execution paths:
      * numpy present  -> one float32 matrix, full dot product (very fast)
      * numpy absent   -> 1-bit sign quantization + Hamming prefilter,
                          then exact dot product on the survivors
    """

    def __init__(self, max_vectors: int = 150_000) -> None:
        self.max_vectors = max_vectors
        # The execution path is fixed at construction so a mid-flight change to
        # HAVE_NUMPY can never leave the two representations half-populated.
        self.use_numpy = HAVE_NUMPY
        self.ids: List[int] = []
        self.ts: List[float] = []
        self.dim: Optional[int] = None
        self.bits: List[int] = []                # fallback path only
        self._vectors: List[bytes] = []          # fallback path only
        self._matrix = None                      # numpy path: (capacity, dim) float32
        self._count = 0                          # numpy path: valid rows in _matrix
        self._ts_np = None                       # numpy path: cached timestamps
        self._last_id = 0
        self._lock = threading.Lock()

    # -- maintenance -------------------------------------------------------
    def clear(self) -> None:
        self.use_numpy = HAVE_NUMPY
        self.ids.clear()
        self.ts.clear()
        self.bits.clear()
        self._vectors.clear()
        self._matrix = None
        self._count = 0
        self._ts_np = None
        self._last_id = 0
        self.dim = None

    def size(self) -> int:
        return len(self.ids)

    def _ensure_capacity(self, needed: int) -> None:
        """Grow the backing matrix geometrically so appends stay amortized O(new)."""
        capacity = 0 if self._matrix is None else int(self._matrix.shape[0])
        if capacity >= needed:
            return
        new_capacity = max(needed, max(1024, capacity * 2))
        grown = _np.empty((new_capacity, self.dim), dtype=_np.float32)
        if self._count:
            grown[: self._count] = self._matrix[: self._count]
        self._matrix = grown

    def refresh(self, store: Store) -> int:
        """Load new rows; rebuild from scratch if rows were deleted underneath us."""
        with self._lock:
            dim = store.dominant_dim()
            if dim is None:
                self.clear()
                return 0
            if self.dim is not None and dim != self.dim:
                self.clear()
            self.dim = dim

            expected = store.count_vectors(dim)
            if expected < len(self.ids):
                # Rows were pruned; cheapest correct move is a rebuild.
                self.clear()
                self.dim = dim

            added = 0
            if self.use_numpy and expected > self._count:
                # Size the matrix once up front so the per-row check below is O(1)
                # and each vector is written straight into its final home: no
                # intermediate join and no second copy.
                self._ensure_capacity(min(expected, self.max_vectors) + 1)
            for row in store.iter_vectors(after_id=self._last_id, dim=dim):
                blob = row["embedding"]
                self._last_id = max(self._last_id, int(row["id"]))
                if not blob or len(blob) != dim * 4:
                    continue
                self.ids.append(int(row["id"]))
                self.ts.append(float(row["ts"]))
                if self.use_numpy:
                    self._ensure_capacity(self._count + 1)
                    self._matrix[self._count] = _np.frombuffer(blob, dtype="<f4")
                    self._count += 1
                else:
                    bits_blob = row["bits"] or b""
                    self.bits.append(int.from_bytes(bits_blob, "big") if bits_blob else 0)
                    self._vectors.append(bytes(blob))
                added += 1
            if self.use_numpy and added:
                self._ts_np = None

            # Enforce the memory cap by dropping the oldest rows.
            if len(self.ids) > self.max_vectors:
                drop = len(self.ids) - self.max_vectors
                keep = len(self.ids) - drop
                del self.ids[:drop]
                del self.ts[:drop]
                if self.use_numpy and self._matrix is not None:
                    self._matrix[:keep] = self._matrix[drop: self._count]
                    self._count = keep
                    self._ts_np = None
                else:
                    del self.bits[:drop]
                    del self._vectors[:drop]
            return added

    # -- search ------------------------------------------------------------
    def search(self, query_vec: Sequence[float], top_k: int = 50,
               since_ts: Optional[float] = None, candidates: int = 400) -> List[Tuple[int, float]]:
        with self._lock:
            if not self.ids or self.dim is None:
                return []
            query = normalize_vector(query_vec)
            if len(query) != self.dim:
                return []

            if self.use_numpy and self._matrix is not None and self._count:
                return self._search_numpy(query, top_k, since_ts)
            return self._search_fallback(query, top_k, since_ts, candidates)

    def _search_numpy(self, query: List[float], top_k: int,
                      since_ts: Optional[float]) -> List[Tuple[int, float]]:
        q = _np.asarray(query, dtype=_np.float32)
        scores = self._matrix[: self._count] @ q
        if since_ts is not None:
            if self._ts_np is None:
                self._ts_np = _np.asarray(self.ts, dtype=_np.float64)
            scores = _np.where(self._ts_np >= since_ts, scores, -_np.inf)
        count = min(top_k, scores.shape[0])
        if count <= 0:
            return []
        idx = _np.argpartition(-scores, count - 1)[:count]
        idx = idx[_np.argsort(-scores[idx])]
        out: List[Tuple[int, float]] = []
        for i in idx:
            score = float(scores[int(i)])
            if score == -_np.inf or math.isnan(score):
                continue
            out.append((self.ids[int(i)], score))
        return out

    def _search_fallback(self, query: List[float], top_k: int, since_ts: Optional[float],
                         candidates: int) -> List[Tuple[int, float]]:
        # Stage 1: Hamming distance on 1-bit signatures (cheap integer work).
        qbits = 0
        for i, value in enumerate(query):
            if value > 0:
                qbits |= 1 << (self.dim - 1 - i)
        pool: List[Tuple[int, int]] = []  # (distance, position)
        for pos, ts in enumerate(self.ts):
            if since_ts is not None and ts < since_ts:
                continue
            pool.append((hamming(qbits, self.bits[pos]), pos))
        if not pool:
            return []
        pool.sort(key=lambda pair: pair[0])
        shortlist = [pos for _, pos in pool[:max(candidates, top_k * 4)]]

        # Stage 2: exact cosine on the shortlist.
        scored: List[Tuple[int, float]] = []
        for pos in shortlist:
            vec = struct.unpack(f"<{self.dim}f", self._vectors[pos])
            score = 0.0
            for a, b in zip(vec, query):
                score += a * b
            scored.append((self.ids[pos], score))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]


# ==========================================================================
# Retrieval
# ==========================================================================

@dataclass
class Hit:
    id: int
    ts: float
    source: str
    origin: str
    text: str
    score: float
    vector_rank: Optional[int] = None
    keyword_rank: Optional[int] = None
    # Empty means this machine. Set when the hit came back from a peer, so an
    # answer can say *where* you read something, not just when.
    peer: str = ""

    def label(self) -> str:
        # Both absolute and relative time: a model asked "what did I do
        # yesterday" should not have to do calendar arithmetic to use a
        # snippet, and weekday names make "last Tuesday" answerable.
        when = datetime.fromtimestamp(self.ts)
        stamp = f"{when.strftime('%a %Y-%m-%d %H:%M')} ({human_age(self.ts)})"
        where = self.origin or self.source
        label = f"{stamp} · {self.source}" + (f" · {where}" if self.origin else "")
        return f"{label} · on {self.peer}" if self.peer else label


class Retriever:
    """Hybrid retrieval: vector search + BM25, fused with RRF and recency."""

    def __init__(self, config: Config, store: Store, index: VectorIndex,
                 client: OllamaClient) -> None:
        self.config = config
        self.store = store
        self.index = index
        self.client = client

    def retrieve(self, query: str, days: Optional[int] = None,
                 top_k: Optional[int] = None) -> List[Hit]:
        cfg = self.config
        top_k = top_k or int(cfg.get("retrieval.top_k", 8))
        rrf_k = float(cfg.get("retrieval.rrf_k", 60))
        candidates = int(cfg.get("retrieval.candidates", 400))
        window_days = days if days is not None else int(cfg.get("retention_days", 30))
        since_ts = now_ts() - window_days * 86400 if window_days > 0 else None

        pool = max(top_k * 6, 50)

        vector_hits: List[Tuple[int, float]] = []
        try:
            self.index.refresh(self.store)
            query_vec = self.client.embed_one(query, cfg.get("embed_model"))
            vector_hits = self.index.search(query_vec, top_k=pool, since_ts=since_ts,
                                            candidates=candidates)
        except (OllamaError, StorageError) as exc:
            LOG.warning("vector search unavailable: %s", exc)

        keyword_hits = self.store.keyword_search(query, limit=pool, since_ts=since_ts)

        fused: Dict[int, float] = {}
        vector_rank: Dict[int, int] = {}
        keyword_rank: Dict[int, int] = {}
        for rank, (row_id, _score) in enumerate(vector_hits):
            fused[row_id] = fused.get(row_id, 0.0) + 1.0 / (rrf_k + rank + 1)
            vector_rank[row_id] = rank + 1
        for rank, (row_id, _score) in enumerate(keyword_hits):
            fused[row_id] = fused.get(row_id, 0.0) + 1.0 / (rrf_k + rank + 1)
            keyword_rank[row_id] = rank + 1
        if not fused:
            return []

        rows = self.store.by_ids(list(fused.keys()))
        max_fused = max(fused.values()) or 1.0
        half_life = float(cfg.get("retrieval.half_life_days", 14.0))
        recency_weight = float(cfg.get("retrieval.recency_weight", 0.35))
        now = now_ts()

        hits: List[Hit] = []
        for row_id, raw in fused.items():
            row = rows.get(row_id)
            if row is None:
                continue
            age_days = max(0.0, (now - float(row["ts"])) / 86400.0)
            decay = 0.5 ** (age_days / half_life) if half_life > 0 else 1.0
            score = (1.0 - recency_weight) * (raw / max_fused) + recency_weight * decay
            hits.append(Hit(
                id=row_id, ts=float(row["ts"]), source=row["source"], origin=row["origin"],
                text=row["text"], score=score,
                vector_rank=vector_rank.get(row_id), keyword_rank=keyword_rank.get(row_id),
            ))

        min_score = float(cfg.get("retrieval.min_score", 0.0))
        hits = [h for h in hits if h.score >= min_score]
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]

    def build_context(self, hits: Sequence[Hit]) -> Tuple[str, List[Hit]]:
        """Assemble a numbered context block within the character budget."""
        budget = int(self.config.get("retrieval.context_chars", 8000))
        used: List[Hit] = []
        parts: List[str] = []
        total = 0
        for hit in hits:
            snippet = hit.text.strip()
            if len(snippet) > 1500:
                snippet = snippet[:1500] + " […]"
            block = f"[{len(used) + 1}] ({hit.label()})\n{snippet}"
            if total + len(block) > budget and used:
                break
            parts.append(block)
            used.append(hit)
            total += len(block)
        return "\n\n".join(parts), used


# ==========================================================================
# Federated query: the other machines you own
# ==========================================================================
#
# The design in one paragraph: every machine keeps its own captures and its
# own database. Nothing syncs, nothing pools, nothing uploads. When you ask a
# question, this machine answers it locally AND asks its peers the same
# question; each peer runs its own retrieval over its own data and sends back
# only the handful of snippets it thinks are relevant. The answers merge, and
# every snippet remembers which machine it came from.
#
# Two consequences worth knowing:
#
#   * Peers never need to agree on an embedding model. The question crosses
#     the wire as text; each node embeds it with whatever it has and searches
#     its own index. A laptop on nomic-embed-text and a desktop on something
#     else federate fine.
#
#   * The transport is deliberately unambitious -- plain HTTP, bound to
#     loopback by default, one shared token. It is meant to be reached over
#     Tailscale or WireGuard, which already solve identity, encryption and NAT
#     traversal far better than anything that belongs in this file. Binding to
#     a non-loopback address without a token is refused outright.


class PeerError(MindError):
    """A peer could not be reached, or refused us."""


PEER_API_VERSION = 1
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "0:0:0:0:0:0:0:1"}
# Bodies are tiny by design. Anything larger is a mistake or an attack.
MAX_PEER_BODY_BYTES = 64 * 1024


def new_peer_token() -> str:
    """A fresh shared secret for a mesh."""
    return secrets.token_urlsafe(32)


def local_node_name(config: "Config") -> str:
    """What this machine calls itself when it answers a peer."""
    configured = str(config.get("peers.node_name") or "").strip()
    if configured:
        return configured
    with contextlib.suppress(OSError):
        host = socket.gethostname().strip()
        if host:
            # "studio.local" and "studio" are the same machine to a human.
            return host.split(".")[0]
    return "this machine"


def is_loopback_host(host: str) -> bool:
    return str(host or "").strip().lower() in _LOOPBACK_HOSTS


@dataclass
class Peer:
    name: str
    url: str
    token: str = ""

    def endpoint(self, path: str) -> Tuple[str, str, int, str, bool]:
        """Split the peer URL into the pieces http.client needs."""
        parsed = urllib.parse.urlparse(self.url)
        secure = parsed.scheme == "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if secure else 80)
        base = parsed.path.rstrip("/")
        return self.url, host, port, base + path, secure


def _coerce_node(raw: Any) -> Optional[Peer]:
    """Accept the several shapes a node survives a shell as."""
    if isinstance(raw, dict):
        url = str(raw.get("url") or "").strip()
        name = str(raw.get("name") or "").strip()
        token = str(raw.get("token") or "").strip()
    elif isinstance(raw, str):
        # "laptop=http://laptop:7717", or a bare URL.
        text = raw.strip().strip("'\"")
        if not text:
            return None
        name, sep, url = text.partition("=")
        if not sep:
            url, name, token = text, "", ""
        else:
            name, url, token = name.strip(), url.strip(), ""
        token = ""
    else:
        return None

    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    if not name:
        name = parsed.hostname.split(".")[0]
    return Peer(name=name, url=url.rstrip("/"), token=token)


def peer_nodes(config: "Config") -> List["Peer"]:
    """Configured peers, with the mesh token filled in where a node lacks one."""
    raw = config.get("peers.nodes", [])
    if isinstance(raw, str):
        # A shell ate the brackets. Recover rather than iterating characters.
        text = raw.strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        raw = [part for part in text.split(",") if part.strip()]
    if not isinstance(raw, list):
        return []

    shared = str(config.get("peers.token") or "").strip()
    peers: List[Peer] = []
    seen = set()
    for item in raw:
        peer = _coerce_node(item)
        if peer is None:
            LOG.warning("ignoring malformed peer entry: %r", item)
            continue
        if not peer.token:
            peer.token = shared
        key = peer.url.lower()
        if key in seen:
            continue
        seen.add(key)
        peers.append(peer)
    return peers


def hit_to_dict(hit: "Hit") -> Dict[str, Any]:
    return {
        "id": hit.id,
        "ts": hit.ts,
        "source": hit.source,
        "origin": hit.origin,
        "text": hit.text,
        "score": hit.score,
        "vector_rank": hit.vector_rank,
        "keyword_rank": hit.keyword_rank,
    }


def hit_from_dict(raw: Dict[str, Any], peer: str = "") -> Optional["Hit"]:
    """Rebuild a Hit from a peer's JSON, distrusting every field."""
    try:
        text = raw["text"]
        if not isinstance(text, str):
            return None
        return Hit(
            id=int(raw.get("id") or 0),
            ts=float(raw.get("ts") or 0.0),
            source=str(raw.get("source") or "peer"),
            origin=str(raw.get("origin") or ""),
            text=text,
            score=float(raw.get("score") or 0.0),
            vector_rank=raw.get("vector_rank") if isinstance(
                raw.get("vector_rank"), int) else None,
            keyword_rank=raw.get("keyword_rank") if isinstance(
                raw.get("keyword_rank"), int) else None,
            peer=peer,
        )
    except (KeyError, TypeError, ValueError):
        return None


# ==========================================================================
# Client: asking the other machines
# ==========================================================================


class PeerClient:
    """Talks to peers. Never raises into a retrieval path -- a machine that is
    asleep is a normal Tuesday, not an error the user should see."""

    def __init__(self, config: "Config") -> None:
        self.config = config
        self.timeout = float(config.get("peers.timeout_sec", 8.0))

    def _request(self, peer: "Peer", path: str, payload: Optional[Dict[str, Any]],
                 timeout: Optional[float] = None) -> Dict[str, Any]:
        _url, host, port, full_path, secure = peer.endpoint(path)
        timeout = timeout or self.timeout
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        if peer.token:
            headers["Authorization"] = f"Bearer {peer.token}"

        conn_cls = http.client.HTTPSConnection if secure else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=timeout)
        try:
            conn.request("POST" if body is not None else "GET", full_path,
                         body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read(MAX_PEER_BODY_BYTES + 1)
            if len(raw) > MAX_PEER_BODY_BYTES:
                raise PeerError(f"{peer.name}: response too large")
            if response.status == 401:
                raise PeerError(f"{peer.name}: rejected our token")
            if response.status == 404:
                raise PeerError(f"{peer.name}: not a mind peer (404 on {path})")
            if response.status >= 400:
                raise PeerError(f"{peer.name}: HTTP {response.status}")
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
            except ValueError as exc:
                raise PeerError(f"{peer.name}: sent something that isn't JSON") from exc
            if not isinstance(data, dict):
                raise PeerError(f"{peer.name}: unexpected response shape")
            return data
        except (http.client.HTTPException, OSError, socket.timeout) as exc:
            raise PeerError(f"{peer.name}: {exc}") from exc
        finally:
            with contextlib.suppress(Exception):
                conn.close()

    def ping(self, peer: "Peer") -> Dict[str, Any]:
        """Identity and liveness. Raises PeerError so `mind peer ping` can report."""
        data = self._request(peer, "/v1/ping", None, timeout=min(self.timeout, 5.0))
        if int(data.get("api") or 0) != PEER_API_VERSION:
            raise PeerError(f"{peer.name}: speaks peer API v{data.get('api')}, "
                            f"we speak v{PEER_API_VERSION}")
        return data

    def retrieve(self, peer: "Peer", query: str, days: Optional[int],
                 top_k: int) -> List["Hit"]:
        """Ask one peer. Returns [] on any failure, and logs why."""
        payload: Dict[str, Any] = {"query": query, "top_k": int(top_k)}
        if days is not None:
            payload["days"] = int(days)
        try:
            data = self._request(peer, "/v1/retrieve", payload)
        except PeerError as exc:
            LOG.info("peer unavailable: %s", exc)
            return []
        raw_hits = data.get("hits")
        if not isinstance(raw_hits, list):
            return []
        # The name YOU gave this machine wins over the name it gives itself:
        # you typed the alias, and "on laptop" is only useful if it matches
        # what you call the laptop.
        name = peer.name or str(data.get("node") or "peer")
        hits: List[Hit] = []
        for item in raw_hits[:top_k]:
            if not isinstance(item, dict):
                continue
            hit = hit_from_dict(item, peer=name)
            if hit is not None:
                hits.append(hit)
        return hits


class FederatedRetriever(Retriever):
    """Local retrieval, plus the same question asked of every peer.

    Merging is done by RANK, not by score. Each node normalises its own scores
    against its own best hit, so the top result on a nearly-empty machine
    scores as highly as the top result on a machine holding a year of work --
    comparing those numbers directly would let a junk peer outrank real local
    context. Reciprocal rank fusion across nodes avoids that entirely, and it
    is the same fusion the local retriever already uses to combine vectors
    with BM25. Ties go to the machine you are sitting at.
    """

    def __init__(self, config: "Config", store: "Store", index: "VectorIndex",
                 client: "OllamaClient", peers: Optional[Sequence["Peer"]] = None,
                 enabled: Optional[bool] = None) -> None:
        super().__init__(config, store, index, client)
        self.peers = list(peers) if peers is not None else peer_nodes(config)
        if enabled is None:
            enabled = bool(config.get("peers.enabled", False))
        self.peers_enabled = bool(enabled)
        self.peer_client = PeerClient(config)
        # Set after each federated retrieve so the CLI can say which machines
        # actually answered without re-pinging them.
        self.last_peers_answered: List[str] = []

    def _ask_peers(self, query: str, days: Optional[int],
                   peer_top_k: int) -> List[Tuple[str, List["Hit"]]]:
        results: List[Tuple[str, List[Hit]]] = []
        if not self.peers:
            return results
        workers = min(len(self.peers), 8)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self.peer_client.retrieve, peer, query, days, peer_top_k): peer
                for peer in self.peers
            }
            for future in concurrent.futures.as_completed(futures):
                peer = futures[future]
                try:
                    hits = future.result()
                except Exception as exc:  # a peer must never break local answers
                    LOG.warning("peer %s failed: %s", peer.name, exc)
                    continue
                if hits:
                    results.append((peer.name, hits))
        return results

    def retrieve(self, query: str, days: Optional[int] = None,
                 top_k: Optional[int] = None) -> List["Hit"]:
        top_k = top_k or int(self.config.get("retrieval.top_k", 8))
        local = super().retrieve(query, days=days, top_k=top_k)
        self.last_peers_answered = []
        if not self.peers_enabled or not self.peers:
            return local

        peer_top_k = max(1, int(self.config.get("peers.peer_top_k", 6)))
        remote = self._ask_peers(query, days, peer_top_k)
        if not remote:
            return local

        rrf_k = float(self.config.get("retrieval.rrf_k", 60))
        ranked: List[Tuple[float, int, float, Hit]] = []
        # is_remote as the second key means a local hit wins a tie.
        for rank, hit in enumerate(local):
            ranked.append((1.0 / (rrf_k + rank + 1), 0, hit.score, hit))
        for name, hits in remote:
            self.last_peers_answered.append(name)
            for rank, hit in enumerate(hits):
                ranked.append((1.0 / (rrf_k + rank + 1), 1, hit.score, hit))

        ranked.sort(key=lambda row: (-row[0], row[1], -row[2]))
        return [row[3] for row in ranked[:top_k]]


def make_retriever(config: "Config", store: "Store", index: "VectorIndex",
                   client: "OllamaClient", allow_peers: bool = True) -> "Retriever":
    """The retriever the CLI should use: federated when peers are configured."""
    if allow_peers and config.get("peers.enabled", False) and peer_nodes(config):
        return FederatedRetriever(config, store, index, client)
    return Retriever(config, store, index, client)


# ==========================================================================
# Server: answering the other machines
# ==========================================================================


class PeerRequestHandler(http.server.BaseHTTPRequestHandler):
    """Read-only. Two routes, fixed. No file paths, no writes, no eval."""

    server_version = f"mind/{VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        LOG.debug("peer-server %s - %s", self.address_string(), fmt % args)

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Nothing here should ever be cached or framed by anything.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with contextlib.suppress(OSError):
            self.wfile.write(body)

    def _authorised(self) -> bool:
        expected = str(getattr(self.server, "token", "") or "")
        if not expected:
            # No token configured. Only reachable on loopback -- serve_peers()
            # refuses to bind anywhere else without one.
            return True
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        offered = header[len(prefix):] if header.startswith(prefix) else ""
        return hmac.compare_digest(offered, expected)

    def _read_body(self) -> Optional[Dict[str, Any]]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_PEER_BODY_BYTES:
            return None
        try:
            raw = self.rfile.read(length)
        except OSError:
            return None
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    # -- routes ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        if path != "/v1/ping":
            self._send_json(404, {"error": "no such endpoint"})
            return
        if not self._authorised():
            self._send_json(401, {"error": "bad token"})
            return
        self._send_json(200, self.server.ping_payload())

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"
        if path != "/v1/retrieve":
            self._send_json(404, {"error": "no such endpoint"})
            return
        if not self._authorised():
            self._send_json(401, {"error": "bad token"})
            return
        payload = self._read_body()
        if payload is None:
            self._send_json(400, {"error": "expected a small JSON object"})
            return

        query = payload.get("query")
        if not isinstance(query, str) or not query.strip():
            self._send_json(400, {"error": "query is required"})
            return
        max_chars = int(self.server.config.get("peers.max_query_chars", 512))
        query = query.strip()[:max_chars]

        max_top_k = int(self.server.config.get("peers.max_top_k", 25))
        try:
            top_k = int(payload.get("top_k") or 6)
        except (TypeError, ValueError):
            top_k = 6
        top_k = max(1, min(top_k, max_top_k))

        days: Optional[int] = None
        if payload.get("days") is not None:
            try:
                days = max(0, int(payload["days"]))
            except (TypeError, ValueError):
                days = None

        try:
            hits = self.server.retrieve(query, days, top_k)
        except Exception as exc:  # never hand a stack trace to the network
            LOG.warning("peer query failed: %s", exc)
            self._send_json(500, {"error": "retrieval failed"})
            return

        self._send_json(200, {
            "api": PEER_API_VERSION,
            "node": self.server.node_name,
            "hits": [hit_to_dict(hit) for hit in hits],
        })


class PeerServer(http.server.ThreadingHTTPServer):
    """Serves retrieval results from a read-only view of this machine's data."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], config: "Config",
                 retriever: "Retriever", node_name: str, token: str,
                 store: Optional["Store"] = None) -> None:
        super().__init__(address, PeerRequestHandler)
        self.config = config
        self.retriever = retriever
        self.node_name = node_name
        self.token = token
        self.store = store
        self._lock = threading.Lock()

    def retrieve(self, query: str, days: Optional[int], top_k: int) -> List["Hit"]:
        # One Store/VectorIndex shared across handler threads, so serialise.
        # Peer queries are rare and cheap; contention is not the problem here,
        # two threads mutating one sqlite connection would be.
        with self._lock:
            return self.retriever.retrieve(query, days=days, top_k=top_k)

    def ping_payload(self) -> Dict[str, Any]:
        entries = None
        if self.store is not None:
            with contextlib.suppress(Exception):
                entries = self.store.count()
        return {
            "api": PEER_API_VERSION,
            "node": self.node_name,
            "version": VERSION,
            "entries": entries,
        }


PEER_EXPOSURE_HELP = (
    "Refusing to listen on a non-loopback address without a token.\n"
    "  This endpoint answers questions about everything you have captured.\n"
    "  Generate one first:   mind peer token --new\n"
    "  Better still, leave the host as 127.0.0.1 and reach this machine over\n"
    "  Tailscale or WireGuard — then the port is never exposed at all."
)


def build_peer_server(config: "Config", paths: "Paths", host: Optional[str] = None,
                      port: Optional[int] = None) -> "PeerServer":
    """Construct the server, refusing the configurations that would hurt."""
    host = host or str(config.get("peers.serve_host", "127.0.0.1"))
    port = int(port or config.get("peers.serve_port", 7717))
    token = str(config.get("peers.token") or "").strip()

    if not is_loopback_host(host) and not token:
        raise MindError(PEER_EXPOSURE_HELP)

    store = Store(paths.db, read_only=True)
    index = VectorIndex(max_vectors=int(config.get("runtime.max_vectors", 150_000)))
    client = OllamaClient(config.get("ollama_url"),
                          timeout=float(config.get("runtime.http_timeout_sec", 120)))
    # Plain Retriever on purpose: a peer answers from its own data only. If
    # peers served federated results they would ask each other in circles.
    retriever = Retriever(config, store, index, client)
    node = local_node_name(config)

    try:
        server = PeerServer((host, port), config, retriever, node, token, store=store)
    except OSError as exc:
        raise MindError(f"cannot listen on {host}:{port} — {exc}") from exc
    return server


# ==========================================================================
# Platform integration
# ==========================================================================

@dataclass
class Focus:
    app: str
    title: str


class PlatformAdapter:
    """Reads clipboard and focused-window state. Degrades to no-ops."""

    name = "generic"

    def __init__(self) -> None:
        self._warned: set = set()

    def _warn_once(self, key: str, message: str) -> None:
        if key not in self._warned:
            self._warned.add(key)
            LOG.warning("%s", message)

    def get_clipboard(self) -> Optional[str]:
        return _pyperclip_paste()

    def get_focus(self) -> Optional[Focus]:
        return None

    def clipboard_available(self) -> bool:
        return self.get_clipboard() is not None or _HAVE_PYPERCLIP

    def focus_available(self) -> bool:
        return self.get_focus() is not None


try:  # optional clipboard fallback for exotic setups
    import pyperclip as _pyperclip

    _HAVE_PYPERCLIP = True
except Exception:  # pragma: no cover
    _pyperclip = None
    _HAVE_PYPERCLIP = False


def _pyperclip_paste() -> Optional[str]:
    if not _HAVE_PYPERCLIP:
        return None
    try:
        return _pyperclip.paste()
    except Exception:
        return None


def _run(cmd: List[str], timeout: float = 3.0) -> Optional[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0)
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return None


class WindowsAdapter(PlatformAdapter):
    """Native Win32 clipboard + foreground window via ctypes (no dependencies)."""

    name = "windows"
    CF_UNICODETEXT = 13
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    def __init__(self) -> None:
        super().__init__()
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        u, k = self.user32, self.kernel32
        u.GetForegroundWindow.restype = wintypes.HWND
        u.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        u.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        u.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
        u.OpenClipboard.argtypes = [wintypes.HWND]
        u.GetClipboardData.argtypes = [wintypes.UINT]
        u.GetClipboardData.restype = wintypes.HANDLE
        k.GlobalLock.argtypes = [wintypes.HANDLE]
        k.GlobalLock.restype = ctypes.c_void_p
        k.GlobalUnlock.argtypes = [wintypes.HANDLE]
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        k.CloseHandle.argtypes = [wintypes.HANDLE]

    def get_clipboard(self) -> Optional[str]:
        ctypes = self.ctypes
        if not self.user32.IsClipboardFormatAvailable(self.CF_UNICODETEXT):
            return None
        # The clipboard is a shared, single-owner resource; other apps hold it briefly.
        for attempt in range(5):
            if self.user32.OpenClipboard(None):
                break
            time.sleep(0.05 * (attempt + 1))
        else:
            return None
        try:
            handle = self.user32.GetClipboardData(self.CF_UNICODETEXT)
            if not handle:
                return None
            pointer = self.kernel32.GlobalLock(handle)
            if not pointer:
                return None
            try:
                return ctypes.c_wchar_p(pointer).value
            finally:
                self.kernel32.GlobalUnlock(handle)
        except Exception:
            return None
        finally:
            with contextlib.suppress(Exception):
                self.user32.CloseClipboard()

    def get_focus(self) -> Optional[Focus]:
        ctypes, wintypes = self.ctypes, self.wintypes
        hwnd = self.user32.GetForegroundWindow()
        if not hwnd:
            return None
        length = self.user32.GetWindowTextLengthW(hwnd)
        title = ""
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            self.user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value or ""
        pid = wintypes.DWORD()
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        app = ""
        if pid.value:
            handle = self.kernel32.OpenProcess(self.PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
            if handle:
                try:
                    size = wintypes.DWORD(1024)
                    buf = ctypes.create_unicode_buffer(size.value)
                    if self.kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                        app = Path(buf.value).stem
                finally:
                    self.kernel32.CloseHandle(handle)
        if not app and not title:
            return None
        return Focus(app=app or "unknown", title=title)


class MacAdapter(PlatformAdapter):
    """macOS via pbpaste and osascript.

    Two separate TCC permissions are involved and they fail differently:
      * Automation (System Events) — without it nothing works at all.
      * Accessibility — without it you get the app name but never a window
        title, silently.
    Both are granted to the *binary* that runs us, so a permission granted to
    Terminal does not carry over to the same script started by launchd.
    """

    name = "macos"

    _FOCUS_SCRIPT = (
        'tell application "System Events"\n'
        '  set frontApp to first application process whose frontmost is true\n'
        '  set appName to name of frontApp\n'
        '  set winTitle to ""\n'
        '  try\n'
        '    set winTitle to name of front window of frontApp\n'
        '  end try\n'
        '  return appName & "\\t" & winTitle\n'
        'end tell'
    )

    # Same query, but reports the AppleScript error instead of swallowing it.
    _PROBE_SCRIPT = (
        'tell application "System Events"\n'
        '  set frontApp to first application process whose frontmost is true\n'
        '  try\n'
        '    set t to name of front window of frontApp\n'
        '    return "TITLE\\t" & t\n'
        '  on error errMsg number errNum\n'
        '    return "ERR\\t" & errNum & "\\t" & errMsg\n'
        '  end try\n'
        'end tell'
    )

    def __init__(self) -> None:
        super().__init__()
        self._failures = 0
        self._retry_after = 0.0
        self.saw_title = False

    def get_clipboard(self) -> Optional[str]:
        out = _run(["pbpaste"])
        if out is None:
            return _pyperclip_paste()
        return out

    def get_focus(self) -> Optional[Focus]:
        # Every call spawns osascript (~50ms). If permission is denied that is
        # pure battery burn, so back off hard once it starts failing.
        if self._failures >= 3 and now_ts() < self._retry_after:
            return None

        out = _run(["osascript", "-e", self._FOCUS_SCRIPT], timeout=5.0)
        if not out:
            self._failures += 1
            self._retry_after = now_ts() + 60.0
            self._warn_once(
                "focus",
                "window focus unavailable — grant Automation/Accessibility access to the app "
                "running this script (System Settings > Privacy & Security). Retrying once a "
                "minute; run `doctor` for the exact error.")
            return None

        self._failures = 0
        parts = out.strip().split("\t")
        app = parts[0].strip() if parts else ""
        title = parts[1].strip() if len(parts) > 1 else ""
        if title:
            self.saw_title = True
        if not app:
            return None
        return Focus(app=app, title=title)

    def probe_focus_permission(self) -> Tuple[str, str]:
        """Return (status, detail) for doctor: ok | no-window | denied | unavailable."""
        out = _run(["osascript", "-e", self._PROBE_SCRIPT], timeout=8.0)
        if out is None:
            return "unavailable", "osascript failed or Automation access was denied"
        text = out.strip()
        if text.startswith("TITLE"):
            title = text.split("\t", 1)[1] if "\t" in text else ""
            return ("ok", title) if title else ("no-window", "frontmost app has no titled window")
        if text.startswith("ERR"):
            pieces = text.split("\t")
            number = pieces[1] if len(pieces) > 1 else "?"
            message = pieces[2] if len(pieces) > 2 else ""
            # -1719 / -25211: not authorized to send events / accessibility off.
            if number.strip() in ("-1719", "-25211", "-1743"):
                return "denied", f"Accessibility not granted (AppleScript error {number})"
            return "no-window", f"{message} ({number})"
        return "unavailable", text[:120]


class LinuxAdapter(PlatformAdapter):
    name = "linux"

    def __init__(self) -> None:
        super().__init__()
        self._clip_cmd = self._detect_clipboard_cmd()
        self._has_xdotool = shutil.which("xdotool") is not None

    @staticmethod
    def _detect_clipboard_cmd() -> Optional[List[str]]:
        if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste"):
            return ["wl-paste", "--no-newline"]
        if shutil.which("xclip"):
            return ["xclip", "-selection", "clipboard", "-o"]
        if shutil.which("xsel"):
            return ["xsel", "--clipboard", "--output"]
        return None

    def get_clipboard(self) -> Optional[str]:
        if self._clip_cmd:
            out = _run(self._clip_cmd)
            if out is not None:
                return out
        return _pyperclip_paste()

    def get_focus(self) -> Optional[Focus]:
        if not self._has_xdotool:
            self._warn_once("focus", "focus capture needs xdotool (X11); install it or disable "
                                     "the focus source")
            return None
        title = _run(["xdotool", "getactivewindow", "getwindowname"])
        pid_out = _run(["xdotool", "getactivewindow", "getwindowpid"])
        app = ""
        if pid_out and pid_out.strip().isdigit():
            comm = Path(f"/proc/{pid_out.strip()}/comm")
            with contextlib.suppress(OSError):
                app = comm.read_text(errors="ignore").strip()
        title = (title or "").strip()
        if not title and not app:
            return None
        return Focus(app=app or "unknown", title=title)


def make_adapter() -> PlatformAdapter:
    try:
        if IS_WINDOWS:
            return WindowsAdapter()
        if IS_MACOS:
            return MacAdapter()
        return LinuxAdapter()
    except Exception as exc:  # pragma: no cover - platform edge cases
        LOG.warning("platform adapter unavailable (%s); falling back to generic", exc)
        return PlatformAdapter()


# ==========================================================================
# Capture pipeline
# ==========================================================================

@dataclass
class CaptureItem:
    source: str
    text: str
    origin: str = ""
    ts: float = field(default_factory=now_ts)
    meta: Dict[str, Any] = field(default_factory=dict)


class Stats:
    """Thread-safe counters surfaced by `status`."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.captured = 0
        self.stored = 0
        self.dropped_secret = 0
        self.dropped_duplicate = 0
        self.dropped_denylist = 0
        self.dropped_queue_full = 0
        self.dropped_expired = 0
        self.embed_failures = 0
        self.started_at = now_ts()

    def bump(self, field_name: str, amount: int = 1) -> None:
        with self._lock:
            setattr(self, field_name, getattr(self, field_name) + amount)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "captured": self.captured,
                "stored": self.stored,
                "dropped_secret": self.dropped_secret,
                "dropped_duplicate": self.dropped_duplicate,
                "dropped_denylist": self.dropped_denylist,
                "dropped_queue_full": self.dropped_queue_full,
                "dropped_expired": self.dropped_expired,
                "embed_failures": self.embed_failures,
                "uptime_sec": now_ts() - self.started_at,
            }


class Producer(threading.Thread):
    """Base class for capture threads."""

    def __init__(self, name: str, ctx: "DaemonContext", interval: float) -> None:
        super().__init__(name=name, daemon=True)
        self.ctx = ctx
        self.interval = max(0.2, float(interval))
        self._stopping = ctx.stop_event  # NB: never name this _stop (shadows Thread._stop)

    def emit(self, item: CaptureItem) -> None:
        self.ctx.submit(item)

    def paused(self) -> bool:
        return self.ctx.is_paused()

    def tick(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self) -> None:
        LOG.info("%s producer started (every %.1fs)", self.name, self.interval)
        while not self._stopping.is_set():
            try:
                if not self.paused():
                    self.tick()
            except Exception:
                LOG.exception("%s producer error", self.name)
            self._stopping.wait(self.interval)
        with contextlib.suppress(Exception):
            self.flush()
        LOG.info("%s producer stopped", self.name)

    def flush(self) -> None:
        """Called on shutdown for producers holding partial state."""


class ClipboardProducer(Producer):
    def __init__(self, ctx: "DaemonContext") -> None:
        cfg = ctx.config
        super().__init__("clipboard", ctx, cfg.get("sources.clipboard.poll_sec", 1.5))
        self.min_chars = int(cfg.get("sources.clipboard.min_chars", 12))
        self.max_chars = int(cfg.get("sources.clipboard.max_chars", 20000))
        self._last_hash: Optional[str] = None

    def tick(self) -> None:
        text = self.ctx.adapter.get_clipboard()
        if not text:
            return
        text = text.strip()
        if len(text) < self.min_chars:
            return
        if len(text) > self.max_chars:
            text = text[: self.max_chars]
        digest = sha256_hex(text)
        if digest == self._last_hash:
            return
        self._last_hash = digest

        focus = self.ctx.current_focus()
        if focus and self.ctx.is_denied(focus):
            self.ctx.stats.bump("dropped_denylist")
            LOG.debug("clipboard capture suppressed while %s is focused", focus.app)
            return
        self.emit(CaptureItem(source="clipboard", text=text,
                              origin=focus.app if focus else "", meta={"chars": len(text)}))


class FocusProducer(Producer):
    """Records focus *sessions* (app + title + duration), not every poll."""

    def __init__(self, ctx: "DaemonContext") -> None:
        cfg = ctx.config
        super().__init__("focus", ctx, cfg.get("sources.focus.poll_sec", 2.0))
        self.min_seconds = float(cfg.get("sources.focus.min_seconds", 8))
        self._current: Optional[Focus] = None
        self._since: float = now_ts()

    def _key(self, focus: Optional[Focus]) -> Tuple[str, str]:
        return (focus.app, focus.title) if focus else ("", "")

    def tick(self) -> None:
        focus = self.ctx.adapter.get_focus()
        self.ctx.set_focus(focus)
        if self._key(focus) == self._key(self._current):
            return
        self._close_session()
        self._current = focus
        self._since = now_ts()

    def _close_session(self) -> None:
        previous, started = self._current, self._since
        if previous is None:
            return
        duration = now_ts() - started
        if duration < self.min_seconds:
            return
        if self.ctx.is_denied(previous):
            self.ctx.stats.bump("dropped_denylist")
            return
        title = previous.title.strip()
        text = f"{previous.app}: {title}" if title else previous.app
        self.emit(CaptureItem(
            source="focus", text=text, origin=previous.app,
            ts=started,
            meta={"duration_sec": round(duration, 1), "title": title},
        ))

    def flush(self) -> None:
        self._close_session()
        self._current = None


class FileProducer(Producer):
    """Indexes text files in configured folders, re-indexing only on change."""

    def __init__(self, ctx: "DaemonContext") -> None:
        cfg = ctx.config
        super().__init__("files", ctx, cfg.get("sources.files.scan_interval_sec", 300))
        self.folders = [Path(p).expanduser() for p in cfg.get("sources.files.folders", [])]
        self.extensions = {e.lower() for e in cfg.get("sources.files.extensions", [])}
        self.exclude_dirs = {d.lower() for d in cfg.get("sources.files.exclude_dirs", [])}
        self.max_bytes = int(cfg.get("sources.files.max_file_bytes", 4_000_000))
        self.max_files = int(cfg.get("sources.files.max_files", 20_000))
        self.store = Store(ctx.paths.db)
        self._first_run = True
        self._warned_missing: set = set()

    def run(self) -> None:
        # Do an initial scan immediately rather than waiting a full interval.
        LOG.info("files producer started (every %.0fs, %d folder(s))",
                 self.interval, len(self.folders))
        while not self._stopping.is_set():
            try:
                if not self.paused():
                    self.tick()
            except Exception:
                LOG.exception("files producer error")
            self._stopping.wait(self.interval)
        self.store.close()
        LOG.info("files producer stopped")

    def _iter_files(self) -> Iterator[Path]:
        seen = 0
        for folder in self.folders:
            if not folder.exists():
                # Warn once per folder, not on every scan — a misconfigured path
                # otherwise repeats the same line in the log forever.
                if str(folder) not in self._warned_missing:
                    self._warned_missing.add(str(folder))
                    LOG.warning("watch folder does not exist: %s — fix it with "
                                "`%s config --set sources.files.folders=[\"<full path>\"]` "
                                "(not repeating this warning)", folder, APP_NAME)
                continue
            self._warned_missing.discard(str(folder))
            stack = [folder]
            while stack:
                current = stack.pop()
                try:
                    entries = list(os.scandir(current))
                except OSError:
                    continue
                for entry in entries:
                    name = entry.name
                    if name.startswith("."):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if name.lower() not in self.exclude_dirs:
                                stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    if Path(name).suffix.lower() not in self.extensions:
                        continue
                    seen += 1
                    if seen > self.max_files:
                        LOG.warning("file scan hit max_files=%d; stopping early", self.max_files)
                        return
                    yield Path(entry.path)

    def tick(self) -> None:
        found: set = set()
        indexed = 0
        for path in self._iter_files():
            key = str(path)
            found.add(key)
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_size > self.max_bytes:
                continue
            state = self.store.file_state(key)
            if state and abs(float(state["mtime"]) - stat.st_mtime) < 0.001 \
                    and int(state["size"]) == stat.st_size:
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="strict")
            except (OSError, UnicodeDecodeError):
                continue  # binary or unreadable: skip quietly
            digest = sha256_hex(raw)
            if state and state["hash"] == digest:
                self.store.upsert_file(key, stat.st_mtime, stat.st_size, digest)
                continue

            self.store.delete_file_chunks(key)  # replace stale chunks atomically enough
            chunks = chunk_text(raw, size=1200, overlap=150)
            for position, chunk in enumerate(chunks):
                self.emit(CaptureItem(
                    source="file", text=chunk, origin=key,
                    ts=stat.st_mtime,
                    meta={"chunk": position, "chunks": len(chunks), "name": path.name},
                ))
            self.store.upsert_file(key, stat.st_mtime, stat.st_size, digest)
            indexed += 1

        # Drop files that disappeared.
        for known in self.store.known_files():
            if known not in found and not Path(known).exists():
                self.store.delete_file_chunks(known)
                self.store.forget_file(known)
                LOG.info("removed index for deleted file %s", known)

        if indexed:
            LOG.info("indexed %d changed file(s)", indexed)
        self._first_run = False


class IngestWorker(threading.Thread):
    """Batches queued captures, embeds them in one request, writes one transaction."""

    def __init__(self, ctx: "DaemonContext") -> None:
        super().__init__(name="ingest", daemon=True)
        self.ctx = ctx
        cfg = ctx.config
        self.batch_size = max(1, int(cfg.get("runtime.embed_batch", 16)))
        self.batch_window = float(cfg.get("runtime.batch_window_sec", 2.0))
        self.dedupe_window_sec = 6 * 3600
        self.max_age_sec = float(cfg.get("retention_days", 30)) * 86400
        # Cap embeddings per minute so a bulk import cannot pin the GPU. Real
        # time capture is a trickle; only backfills ever approach this.
        self.max_embeds_per_min = int(cfg.get("runtime.max_embeds_per_min", 300))
        self._embed_window_start = now_ts()
        self._embedded_this_window = 0
        # In-memory LRU of recent hashes: catches duplicates inside a single
        # batch (which are not in the DB yet) and avoids a query per item.
        self._recent: "OrderedDict[str, float]" = OrderedDict()
        self._recent_max = 8192
        self.store = Store(ctx.paths.db)
        self.redactor = Redactor(
            skip_secrets=bool(cfg.get("privacy.skip_secrets", True)),
            entropy_guard=bool(cfg.get("privacy.entropy_guard", True)),
        )

    def run(self) -> None:
        LOG.info("ingest worker started (batch=%d, window=%.1fs)", self.batch_size, self.batch_window)
        batch: List[CaptureItem] = []
        deadline = now_ts() + self.batch_window
        while not self.ctx.stop_event.is_set() or not self.ctx.queue.empty() or batch:
            timeout = max(0.05, deadline - now_ts())
            try:
                item = self.ctx.queue.get(timeout=timeout)
                batch.append(item)
                self.ctx.queue.task_done()
            except queue.Empty:
                pass

            flush_due = now_ts() >= deadline or len(batch) >= self.batch_size
            if self.ctx.stop_event.is_set() and self.ctx.queue.empty():
                flush_due = True
            if batch and flush_due:
                try:
                    self._flush(batch)
                except Exception:
                    LOG.exception("ingest flush failed; %d item(s) dropped", len(batch))
                batch = []
                deadline = now_ts() + self.batch_window
            elif not batch:
                deadline = now_ts() + self.batch_window

            if self.ctx.stop_event.is_set() and self.ctx.queue.empty() and not batch:
                break
        self.store.close()
        LOG.info("ingest worker stopped")

    def _accept(self, item: CaptureItem) -> bool:
        text = normalize_ws(item.text)
        if not text:
            return False
        item.text = text
        if item.ts < now_ts() - self.max_age_sec:
            # Retention would delete this within the hour; do not spend GPU
            # time embedding it in the first place.
            self.ctx.stats.bump("dropped_expired")
            return False
        reason = self.redactor.reason(text)
        if reason:
            self.ctx.stats.bump("dropped_secret")
            LOG.info("dropped %s capture (%s)", item.source, reason)
            return False
        digest = sha256_hex(text)
        item.meta.setdefault("hash", digest)
        if item.source != "file":
            key = f"{item.source}:{digest}"
            cached = self._recent.get(key)
            if cached is not None and (now_ts() - cached) < self.dedupe_window_sec:
                self.ctx.stats.bump("dropped_duplicate")
                return False
            if self.store.seen_recently(digest, item.source, self.dedupe_window_sec):
                self._remember(key)
                self.ctx.stats.bump("dropped_duplicate")
                return False
            self._remember(key)
        return True

    def _remember(self, key: str) -> None:
        self._recent[key] = now_ts()
        self._recent.move_to_end(key)
        while len(self._recent) > self._recent_max:
            self._recent.popitem(last=False)

    def _throttle(self, count: int) -> None:
        """Sleep if we are embedding faster than the configured ceiling."""
        if self.max_embeds_per_min <= 0:
            return
        elapsed = now_ts() - self._embed_window_start
        if elapsed >= 60.0:
            self._embed_window_start = now_ts()
            self._embedded_this_window = 0
            elapsed = 0.0
        self._embedded_this_window += count
        if self._embedded_this_window > self.max_embeds_per_min:
            pause = max(0.0, 60.0 - elapsed)
            if pause > 0:
                LOG.info("embedding rate limit reached (%d/min); pausing %.0fs to let the "
                         "GPU breathe", self.max_embeds_per_min, pause)
                self.ctx.stop_event.wait(pause)
            self._embed_window_start = now_ts()
            self._embedded_this_window = 0

    def _flush(self, batch: List[CaptureItem]) -> None:
        accepted = [item for item in batch if self._accept(item)]
        if not accepted:
            return
        self._throttle(len(accepted))
        vectors: List[Optional[List[float]]] = [None] * len(accepted)
        try:
            embedded = self.ctx.client.embed([item.text for item in accepted],
                                             self.ctx.config.get("embed_model"))
            if len(embedded) == len(accepted):
                vectors = list(embedded)
        except OllamaError as exc:
            self.ctx.stats.bump("embed_failures")
            LOG.warning("embedding failed (%s); storing %d item(s) for later backfill",
                        exc, len(accepted))

        rows = []
        for item, vector in zip(accepted, vectors):
            rows.append({
                "ts": item.ts,
                "source": item.source,
                "origin": item.origin,
                "text": item.text,
                "meta": item.meta,
                "hash": item.meta.get("hash") or sha256_hex(item.text),
                "vector": vector,
            })
        written = self.store.insert_batch(rows)
        self.ctx.stats.bump("stored", written)
        LOG.debug("stored %d capture(s)", written)


class MaintenanceWorker(threading.Thread):
    """Heartbeat, retention pruning, and embedding backfill."""

    def __init__(self, ctx: "DaemonContext") -> None:
        super().__init__(name="maintenance", daemon=True)
        self.ctx = ctx
        self.store = Store(ctx.paths.db)
        self.tick_sec = 5.0
        self._last_prune = 0.0
        self._last_vacuum = now_ts()
        self._last_summary = now_ts()
        self.summary_sec = float(ctx.config.get("runtime.summary_sec", 300.0))
        # Persisted, NOT reset to now on startup. Anchoring it to process start
        # meant every restart pushed the next reflection a full day out, so a
        # daemon that is stopped even once a day never built a profile at all.
        try:
            self._last_reflect = float(self.store.get_meta("last_reflect_ts") or 0.0)
        except (ValueError, TypeError):
            self._last_reflect = 0.0

    def run(self) -> None:
        LOG.info("maintenance worker started")
        while not self.ctx.stop_event.is_set():
            try:
                self._heartbeat()
                self._backfill()
                self._prune()
                self._summary()
                self._reflect()
            except Exception:
                LOG.exception("maintenance error")
            self.ctx.stop_event.wait(self.tick_sec)
        with contextlib.suppress(Exception):
            self._heartbeat(final=True)
        self.store.close()
        LOG.info("maintenance worker stopped")

    def _heartbeat(self, final: bool = False) -> None:
        payload = {
            "pid": os.getpid(),
            "ts": now_ts(),
            "running": not final,
            "paused": self.ctx.is_paused(),
            "sources": self.ctx.config.enabled_sources(),
            "queue_depth": self.ctx.queue.qsize(),
            "stats": self.ctx.stats.snapshot(),
            "version": VERSION,
        }
        tmp = self.ctx.paths.heartbeat.with_suffix(".tmp")
        with contextlib.suppress(OSError):
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            tmp.replace(self.ctx.paths.heartbeat)

    def _backfill(self) -> None:
        pending = self.store.pending_embeddings(limit=32)
        if not pending:
            return
        texts = [row["text"] for row in pending]
        try:
            vectors = self.ctx.client.embed(texts, self.ctx.config.get("embed_model"))
        except OllamaError:
            return  # server still down; try again next tick
        if len(vectors) != len(pending):
            return
        self.store.set_embeddings([(int(row["id"]), vec) for row, vec in zip(pending, vectors)])
        LOG.info("backfilled embeddings for %d capture(s)", len(pending))

    def _summary(self) -> None:
        """Periodic proof-of-life. Successful captures are only logged at DEBUG,
        so without this a perfectly healthy daemon writes nothing for hours and
        looks broken."""
        if now_ts() - self._last_summary < self.summary_sec:
            return
        self._last_summary = now_ts()
        snapshot = self.ctx.stats.snapshot()
        dropped = (snapshot["dropped_secret"] + snapshot["dropped_duplicate"]
                   + snapshot["dropped_denylist"] + snapshot["dropped_queue_full"])
        LOG.info(
            "alive: %d stored, %d captured, %d dropped (secret %d / dup %d / denied %d), "
            "%d total in db, %d awaiting embedding, queue %d",
            snapshot["stored"], snapshot["captured"], dropped,
            snapshot["dropped_secret"], snapshot["dropped_duplicate"],
            snapshot["dropped_denylist"],
            self.store.count(), self.store.count_pending(), self.ctx.queue.qsize())
        if snapshot["captured"] == 0 and snapshot["uptime_sec"] > 600:
            LOG.warning("no captures at all in %d minutes — check that the enabled sources can "
                        "actually read (run `%s doctor`)",
                        int(snapshot["uptime_sec"] // 60), APP_NAME)

    def _reflect(self) -> None:
        """Nightly consolidation: distil captures into durable profile facts."""
        if not self.ctx.config.get("profile.enabled", True):
            return
        interval = float(self.ctx.config.get("profile.reflect_interval_sec", 86400))
        profile = ProfileStore(self.ctx.config, self.store)
        # The FIRST pass runs much sooner than the nightly cadence. Waiting a
        # full day to show anything makes the feature look broken, and there is
        # usually plenty to learn from the first hour of captures.
        if not profile.facts():
            interval = min(interval, float(
                self.ctx.config.get("profile.first_reflect_sec", 900)))
        if now_ts() - self._last_reflect < interval:
            return
        # Check the model BEFORE consuming the slot. Stamping the clock first
        # meant a momentary Ollama outage cost a whole interval — 15 minutes at
        # first, a full day once any fact existed.
        if not self.ctx.client.is_up():
            return
        self._last_reflect = now_ts()
        with contextlib.suppress(Exception):
            self.store.set_meta("last_reflect_ts", str(self._last_reflect))
        reflector = Reflector(self.ctx.config, self.store, self.ctx.client, profile)
        summary = reflector.reflect()
        if summary.get("added") or summary.get("reinforced"):
            LOG.info("reflection: +%d new, %d reinforced, %d sensitive dropped, from %d obs",
                     summary["added"], summary["reinforced"],
                     summary["skipped_sensitive"], summary["observations"])

    def _prune(self) -> None:
        if now_ts() - self._last_prune < 3600:
            return
        self._last_prune = now_ts()
        removed = self.store.prune(int(self.ctx.config.get("retention_days", 30)),
                                   int(self.ctx.config.get("max_entries", 0)))
        if removed:
            LOG.info("pruned %d expired capture(s)", removed)
        stale = self.store.knowledge_prune()
        if stale:
            LOG.info("pruned %d expired cached answer(s)", stale)
        if now_ts() - self._last_vacuum > 7 * 86400:
            self._last_vacuum = now_ts()
            self.store.vacuum()
            LOG.info("database vacuumed")


# ==========================================================================
# Daemon
# ==========================================================================

class SingleInstanceLock:
    """Cross-platform advisory lock so two daemons never run at once."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._fh = open(self.path, "a+")
        except OSError:
            return False
        try:
            if IS_WINDOWS:
                import msvcrt

                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._fh.close()
            self._fh = None
            return False
        with contextlib.suppress(OSError):
            self._fh.seek(0)
            self._fh.truncate()
            self._fh.write(str(os.getpid()))
            self._fh.flush()
        return True

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if IS_WINDOWS:
                import msvcrt

                self._fh.seek(0)
                with contextlib.suppress(OSError):
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                with contextlib.suppress(OSError):
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            with contextlib.suppress(OSError):
                self._fh.close()
            self._fh = None

    def held_by(self) -> Optional[int]:
        with contextlib.suppress(OSError, ValueError):
            return int(self.path.read_text().strip())
        return None


class DaemonContext:
    """Shared state for the capture daemon."""

    def __init__(self, config: Config, paths: Paths, client: OllamaClient,
                 adapter: PlatformAdapter) -> None:
        self.config = config
        self.paths = paths
        self.client = client
        self.adapter = adapter
        self.queue: "queue.Queue[CaptureItem]" = queue.Queue(
            maxsize=int(config.get("runtime.queue_max", 5000)))
        self.stop_event = threading.Event()
        self.stats = Stats()
        self._focus_lock = threading.Lock()
        self._focus: Optional[Focus] = None
        self._deny_apps = [a.lower() for a in config.get("privacy.app_denylist", [])]
        self._deny_titles = [t.lower() for t in config.get("privacy.title_denylist", [])]

    # -- focus sharing -----------------------------------------------------
    def set_focus(self, focus: Optional[Focus]) -> None:
        with self._focus_lock:
            self._focus = focus

    def current_focus(self) -> Optional[Focus]:
        with self._focus_lock:
            if self._focus is not None:
                return self._focus
        # Focus producer may be disabled; ask the adapter directly (cheap enough).
        focus = self.adapter.get_focus()
        self.set_focus(focus)
        return focus

    # -- policy ------------------------------------------------------------
    def is_denied(self, focus: Optional[Focus]) -> bool:
        if focus is None:
            return False
        app = (focus.app or "").lower()
        title = (focus.title or "").lower()
        if any(pattern in app for pattern in self._deny_apps):
            return True
        if any(pattern in title for pattern in self._deny_apps):
            return True
        return any(pattern in title for pattern in self._deny_titles)

    def is_paused(self) -> bool:
        return self.paths.paused.exists()

    def submit(self, item: CaptureItem) -> None:
        self.stats.bump("captured")
        try:
            self.queue.put_nowait(item)
        except queue.Full:
            self.stats.bump("dropped_queue_full")
            LOG.warning("capture queue full; dropped a %s item", item.source)


class Daemon:
    def __init__(self, config: Config, paths: Paths) -> None:
        self.config = config
        self.paths = paths
        self.lock = SingleInstanceLock(paths.lock)
        self.client = OllamaClient(
            config.get("ollama_url"),
            timeout=float(config.get("runtime.http_timeout_sec", 120)),
            chat_timeout=float(config.get("runtime.chat_timeout_sec", 600)),
        )
        self.ctx = DaemonContext(config, paths, self.client, make_adapter())
        self.threads: List[threading.Thread] = []

    def _build_threads(self) -> List[threading.Thread]:
        threads: List[threading.Thread] = [IngestWorker(self.ctx), MaintenanceWorker(self.ctx)]
        if self.config.get("sources.clipboard.enabled"):
            threads.append(ClipboardProducer(self.ctx))
        if self.config.get("sources.focus.enabled"):
            threads.append(FocusProducer(self.ctx))
        if self.config.get("sources.files.enabled") and self.config.get("sources.files.folders"):
            threads.append(FileProducer(self.ctx))
        if self.config.get("sources.browser.enabled"):
            threads.append(BrowserProducer(self.ctx))
        return threads

    def run(self) -> int:
        if not self.lock.acquire():
            holder = self.lock.held_by()
            raise MindError(
                "another capture process is already running"
                + (f" (pid {holder})" if holder else "")
                + f". Stop it first, or run `{APP_NAME} status`."
            )
        try:
            sources = self.config.enabled_sources()
            if not sources:
                raise MindError("no capture sources are enabled. Run `setup` and turn one on.")
            if not self.client.is_up():
                LOG.warning("Ollama is not reachable at %s — captures will be stored without "
                            "embeddings and backfilled automatically once it returns",
                            self.config.get("ollama_url"))

            self._install_signal_handlers()
            self.threads = self._build_threads()
            for thread in self.threads:
                thread.start()
            LOG.info("capture running: sources=%s retention=%sd pid=%d",
                     ",".join(sources), self.config.get("retention_days"), os.getpid())

            while not self.ctx.stop_event.is_set():
                self.ctx.stop_event.wait(1.0)
                if not any(t.is_alive() for t in self.threads):
                    break
            return 0
        finally:
            self.shutdown()

    def _install_signal_handlers(self) -> None:
        def handler(signum, _frame):
            LOG.info("received signal %s; shutting down", signum)
            self.ctx.stop_event.set()

        for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, sig_name, None)
            if sig is not None:
                with contextlib.suppress(ValueError, OSError):
                    signal.signal(sig, handler)

    def shutdown(self) -> None:
        self.ctx.stop_event.set()
        for thread in self.threads:
            with contextlib.suppress(RuntimeError):
                thread.join(timeout=20.0)
        with contextlib.suppress(Exception):
            self.client.close()
        self.lock.release()
        LOG.info("capture stopped cleanly")


# ==========================================================================
# Browser history capture
# ==========================================================================

# Firefox stores visit times as PRTime: MICROseconds since the Unix epoch.
# Chromium stores them as microseconds since 1601-01-01 (the Windows epoch).
# Getting either wrong puts every visit in the wrong century.
_CHROMIUM_EPOCH_OFFSET = 11_644_473_600  # seconds between 1601-01-01 and 1970-01-01
# Safari stores visit_time as CFAbsoluteTime: seconds since 2001-01-01 UTC.
_SAFARI_EPOCH_OFFSET = 978_307_200       # seconds between 1970-01-01 and 2001-01-01


def safari_history_file() -> Optional[Path]:
    """Safari's history DB, if present. macOS only, and TCC-protected —
    reading it needs Full Disk Access for whichever binary runs the daemon."""
    if not IS_MACOS:
        return None
    candidate = Path.home() / "Library" / "Safari" / "History.db"
    return candidate if candidate.exists() else None


def firefox_profile_dirs() -> List[Path]:
    """Locate Firefox profile directories from profiles.ini."""
    if IS_WINDOWS:
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Mozilla" / "Firefox"
    elif IS_MACOS:
        root = Path.home() / "Library" / "Application Support" / "Firefox"
    else:
        root = Path.home() / ".mozilla" / "firefox"

    ini = root / "profiles.ini"
    if not ini.exists():
        return []

    import configparser

    parser = configparser.ConfigParser()
    with contextlib.suppress(Exception):
        parser.read(ini, encoding="utf-8")

    found: List[Path] = []
    for section in parser.sections():
        raw_path = parser.get(section, "Path", fallback=None)
        if not raw_path:
            continue
        is_relative = parser.get(section, "IsRelative", fallback="1").strip() == "1"
        candidate = (root / raw_path) if is_relative else Path(raw_path)
        if (candidate / "places.sqlite").exists():
            found.append(candidate)
    return found


def chromium_history_files() -> List[Tuple[str, Path]]:
    """Locate History databases for Chrome/Edge/Brave/Chromium."""
    if IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        roots = {
            "chrome": base / "Google" / "Chrome" / "User Data",
            "edge": base / "Microsoft" / "Edge" / "User Data",
            "brave": base / "BraveSoftware" / "Brave-Browser" / "User Data",
        }
    elif IS_MACOS:
        base = Path.home() / "Library" / "Application Support"
        roots = {
            "chrome": base / "Google" / "Chrome",
            "edge": base / "Microsoft Edge",
            "brave": base / "BraveSoftware" / "Brave-Browser",
            "arc": base / "Arc" / "User Data",   # Arc is Chromium-based, popular on Mac
            "vivaldi": base / "Vivaldi",
            "opera": base / "com.operasoftware.Opera",
        }
    else:
        base = Path.home() / ".config"
        roots = {
            "chrome": base / "google-chrome",
            "chromium": base / "chromium",
            "brave": base / "BraveSoftware" / "Brave-Browser",
        }

    found: List[Tuple[str, Path]] = []
    for name, root in roots.items():
        if not root.exists():
            continue
        # Some Chromium browsers (Opera) keep History in the root, not a
        # Default/ profile; check both shapes.
        for profile in ("", "Default", "Profile 1", "Profile 2", "Profile 3"):
            history = (root / profile / "History") if profile else (root / "History")
            if history.exists():
                label = f"{name}:{profile}" if profile else name
                found.append((label, history))
    return found


def sanitize_url(url: str, strip_query: bool = True,
                 keep_params: Optional[Dict[str, List[str]]] = None) -> str:
    """Drop tracking parameters while keeping the ones that identify content.

    YouTube's video id lives in ?v=, so a blanket strip would make every video
    URL useless; everything else is usually session or campaign junk that can
    carry credentials.
    """
    keep_params = keep_params or {}
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if not strip_query or not parsed.query:
        return url

    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    allowed: List[str] = []
    for domain, params in keep_params.items():
        if host == domain.lower() or host.endswith("." + domain.lower()):
            allowed = [p.lower() for p in params]
            break

    if not allowed:
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    kept = [(k, v) for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=False)
            if k.lower() in allowed]
    query = urllib.parse.urlencode(kept)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _snapshot_db(path: Path) -> Optional[Path]:
    """Copy a browser DB before reading it — the browser holds a write lock."""
    import tempfile

    try:
        target_dir = Path(tempfile.mkdtemp(prefix="mind-hist-"))
        target = target_dir / path.name
        shutil.copy2(path, target)
        # WAL sidecars carry recent visits that are not in the main file yet.
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists():
                with contextlib.suppress(OSError):
                    shutil.copy2(sidecar, Path(str(target) + suffix))
        return target
    except OSError as exc:
        LOG.warning("could not snapshot %s: %s", path, exc)
        return None


def _read_sqlite_rows(db_path: Path, sql: str, params: Sequence[Any]) -> List[Tuple]:
    snapshot = _snapshot_db(db_path)
    if snapshot is None:
        return []
    try:
        conn = sqlite3.connect(f"file:{snapshot}?mode=ro", uri=True, timeout=5.0)
        try:
            return list(conn.execute(sql, tuple(params)))
        finally:
            conn.close()
    except DB_ERRORS as exc:
        LOG.warning("could not read %s: %s", db_path.name, exc)
        return []
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(snapshot.parent, ignore_errors=True)


class BrowserProducer(Producer):
    """Reads visit history straight from the browser's own database.

    Window titles tell you a page was open; only history gives you the URL,
    which is what makes 'go fetch that page' possible at all.
    """

    FIREFOX_SQL = (
        "SELECT v.id, v.visit_date, p.url, p.title "
        "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id "
        "WHERE v.id > ? ORDER BY v.id LIMIT ?"
    )
    CHROMIUM_SQL = (
        "SELECT v.id, v.visit_time, u.url, u.title "
        "FROM visits v JOIN urls u ON u.id = v.url "
        "WHERE v.id > ? ORDER BY v.id LIMIT ?"
    )
    SAFARI_SQL = (
        "SELECT v.id, v.visit_time, i.url, v.title "
        "FROM history_visits v JOIN history_items i ON i.id = v.history_item "
        "WHERE v.id > ? ORDER BY v.id LIMIT ?"
    )

    def __init__(self, ctx: "DaemonContext") -> None:
        cfg = ctx.config
        super().__init__("browser", ctx, cfg.get("sources.browser.poll_sec", 60))
        self.wanted = {b.lower() for b in cfg.get("sources.browser.browsers", [])}
        self.strip_query = bool(cfg.get("sources.browser.strip_query", True))
        self.keep_params = cfg.get("sources.browser.keep_params", {}) or {}
        self.denylist = [d.lower() for d in cfg.get("sources.browser.domain_denylist", [])]
        self.batch = int(cfg.get("sources.browser.batch", 500))
        # Never import history older than the retention window: those rows
        # would be embedded on the GPU and then deleted by the pruner within
        # the hour. On first run this is the difference between ingesting a
        # month and ingesting five years of browsing.
        self.max_age_sec = float(cfg.get("retention_days", 30)) * 86400
        self.store = Store(ctx.paths.db)

    def _checkpoint_key(self, source_id: str) -> str:
        return f"browser_checkpoint:{source_id}"

    def _denied(self, url: str) -> bool:
        host = ""
        with contextlib.suppress(ValueError):
            host = (urllib.parse.urlsplit(url).hostname or "").lower()
        return any(pattern in host for pattern in self.denylist if pattern)

    def _ingest(self, source_id: str, db_path: Path, sql: str, to_epoch) -> int:
        last = int(self.store.get_meta(self._checkpoint_key(source_id), "0") or 0)
        rows = _read_sqlite_rows(db_path, sql, (last, self.batch))
        if not rows:
            return 0
        highest = last
        emitted = 0
        skipped_old = 0
        cutoff = now_ts() - self.max_age_sec
        for visit_id, raw_time, url, title in rows:
            highest = max(highest, int(visit_id))
            if not url or not url.startswith(("http://", "https://")):
                continue
            visited_at = to_epoch(raw_time)
            if visited_at < cutoff:
                skipped_old += 1
                continue
            if self._denied(url):
                self.ctx.stats.bump("dropped_denylist")
                continue
            clean = sanitize_url(url, self.strip_query, self.keep_params)
            text = (title or "").strip() or clean
            self.emit(CaptureItem(
                source="browser", text=text, origin=clean,
                ts=visited_at,
                meta={"url": clean, "title": title or "", "browser": source_id.split(":")[0]},
            ))
            emitted += 1
        if highest > last:
            self.store.set_meta(self._checkpoint_key(source_id), str(highest))
        if skipped_old:
            LOG.info("%s: skipped %d visit(s) older than the %d-day retention window",
                     source_id, skipped_old, int(self.max_age_sec // 86400))
        return emitted

    def tick(self) -> None:
        total = 0
        if "firefox" in self.wanted:
            for index, profile in enumerate(firefox_profile_dirs()):
                total += self._ingest(f"firefox:{index}", profile / "places.sqlite",
                                      self.FIREFOX_SQL, lambda t: float(t or 0) / 1_000_000.0)
        for name, history in chromium_history_files():
            if name.split(":")[0] not in self.wanted:
                continue
            total += self._ingest(
                name, history, self.CHROMIUM_SQL,
                lambda t: (float(t or 0) / 1_000_000.0) - _CHROMIUM_EPOCH_OFFSET)
        if "safari" in self.wanted:
            safari = safari_history_file()
            if safari is not None:
                total += self._ingest(
                    "safari", safari, self.SAFARI_SQL,
                    lambda t: float(t or 0) + _SAFARI_EPOCH_OFFSET)
        if total:
            LOG.info("captured %d browser visit(s)", total)

    def run(self) -> None:
        LOG.info("browser producer started (every %.0fs, %s)",
                 self.interval, ",".join(sorted(self.wanted)) or "none")
        while not self._stopping.is_set():
            try:
                if not self.paused():
                    self.tick()
            except Exception:
                LOG.exception("browser producer error")
            self._stopping.wait(self.interval)
        self.store.close()
        LOG.info("browser producer stopped")


# ==========================================================================
# Deterministic time resolution
# ==========================================================================

_WEEKDAYS = {name.lower(): index for index, name in enumerate(
    ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"])}

_MONTHS = {name.lower(): index + 1 for index, name in enumerate(
    ["january", "february", "march", "april", "may", "june", "july",
     "august", "september", "october", "november", "december"])}


def resolve_time_expression(expression: str, now: Optional[datetime] = None
                            ) -> Optional[Tuple[float, float, str]]:
    """Turn "tuesday around 5pm" into an absolute (start, end, description).

    Deliberately Python rather than the model: small models are unreliable at
    calendar arithmetic, and a wrong day silently produces a confident answer
    about the wrong evening.
    """
    now = now or datetime.now()
    text = expression.lower().strip()
    if not text:
        return None

    # --- clock time, if any -------------------------------------------------
    hour: Optional[int] = None
    minute = 0
    clock = re.search(r"\b(\d{1,2})(?::(\d{2}))?\s*(am|pm|a\.m\.|p\.m\.)\b", text)
    if clock:
        hour = int(clock.group(1)) % 12
        minute = int(clock.group(2) or 0)
        if clock.group(3).startswith("p"):
            hour += 12
    else:
        clock24 = re.search(r"\b(\d{1,2}):(\d{2})\b", text)
        if clock24:
            hour, minute = int(clock24.group(1)), int(clock24.group(2))
        elif re.search(r"\bnoon\b", text):
            hour = 12
        elif re.search(r"\bmidnight\b", text):
            hour = 0
        elif re.search(r"\bmorning\b", text):
            hour = 9
        elif re.search(r"\bafternoon\b", text):
            hour = 15
        elif re.search(r"\bevening\b|\btonight\b", text):
            hour = 20

    # --- the day ------------------------------------------------------------
    day: Optional[datetime] = None
    if re.search(r"\btoday\b", text):
        day = now
    elif re.search(r"\byesterday\b", text):
        day = now - timedelta(days=1)
    elif re.search(r"\bday before yesterday\b", text):
        day = now - timedelta(days=2)
    elif re.search(r"\btomorrow\b", text):
        day = now + timedelta(days=1)

    if day is None:
        explicit = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", text)
        if explicit:
            with contextlib.suppress(ValueError):
                day = datetime(int(explicit.group(1)), int(explicit.group(2)),
                               int(explicit.group(3)))

    if day is None:
        month_day = re.search(r"\b(" + "|".join(_MONTHS) + r")\s+(\d{1,2})\b", text)
        if month_day:
            with contextlib.suppress(ValueError):
                day = datetime(now.year, _MONTHS[month_day.group(1)], int(month_day.group(2)))
                if day > now + timedelta(days=1):
                    day = day.replace(year=now.year - 1)

    if day is None:
        for name, index in _WEEKDAYS.items():
            if re.search(r"\b" + name + r"\b", text):
                delta = (now.weekday() - index) % 7
                if delta == 0 and not re.search(r"\btoday\b", text):
                    delta = 7 if re.search(r"\blast\b", text) else 0
                day = now - timedelta(days=delta)
                if re.search(r"\blast\b", text) and delta < 7:
                    day -= timedelta(days=7)
                break

    if day is None:
        ago = re.search(r"\b(\d+)\s+(day|week|hour)s?\s+ago\b", text)
        if ago:
            amount = int(ago.group(1))
            unit = ago.group(2)
            if unit == "hour":
                end = now - timedelta(hours=amount) + timedelta(minutes=30)
                start = end - timedelta(hours=1)
                return start.timestamp(), end.timestamp(), f"{amount} hour(s) ago"
            days = amount * (7 if unit == "week" else 1)
            day = now - timedelta(days=days)

    if day is None and re.search(r"\bthis week\b", text):
        start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0,
                                                              microsecond=0)
        return start.timestamp(), now.timestamp(), "this week"
    if day is None and re.search(r"\blast week\b", text):
        this_monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0,
                                                                    microsecond=0)
        start = this_monday - timedelta(days=7)
        return start.timestamp(), this_monday.timestamp(), "last week"

    if day is None:
        return None

    if hour is None:
        start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        return start.timestamp(), end.timestamp(), start.strftime("%A %Y-%m-%d (all day)")

    # "around 5pm" is a window, not an instant.
    centre = day.replace(hour=hour, minute=minute, second=0, microsecond=0)
    fuzzy = bool(re.search(r"\baround\b|\babout\b|\bish\b|~", text))
    span = timedelta(minutes=45 if fuzzy else 30)
    start, end = centre - span, centre + span
    minutes = int(span.total_seconds() // 60)
    description = f"{centre.strftime('%A %Y-%m-%d %H:%M')} ± {minutes}m"
    return start.timestamp(), end.timestamp(), description


# ==========================================================================
# Web access
# ==========================================================================

class NetworkDenied(MindError):
    """Raised when policy forbids a request. Never retried."""


class _HttpError(MindError):
    """A non-OK HTTP status, carrying the code so a caller can decide to retry."""

    def __init__(self, status: int, url: str) -> None:
        super().__init__(f"{url} returned HTTP {status}")
        self.status = status


class _ReadableExtractor:
    """Pull the main article out of a page, the way a reader-mode does.

    Handing a small local model an entire page is expensive and actively
    harmful: navigation, cookie banners, sidebars, "related stories" and
    comment threads crowd out the few paragraphs that answer the question, and
    an 8k context fills with furniture. So candidate containers are scored by
    how much real prose they hold versus how much of their text is link
    anchors — menus are nearly all links, articles are nearly none — and the
    winner is rendered alone.

    Pure stdlib. Falls back to whole-document text whenever scoring produces
    something suspiciously small, so an unusual page degrades to the old
    behaviour rather than to nothing.
    """

    # Furniture: never contributes text.
    SKIP = {"script", "style", "noscript", "nav", "footer", "header", "form",
            "svg", "aside", "iframe", "button", "select", "template", "figure",
            "figcaption", "picture", "video", "audio"}
    # Containers worth scoring as a possible article body.
    CANDIDATES = {"article", "main", "div", "section", "td"}
    # class/id substrings that mark boilerplate, and ones that mark content.
    BAD_HINT = re.compile(
        r"(nav|menu|sidebar|side-bar|footer|header|masthead|comment|cookie|consent|"
        r"banner|promo|related|share|social|newsletter|subscribe|signup|popup|modal|"
        r"advert|adsense|breadcrumb|pagination|widget|toolbar|skip-link|disclaimer)", re.I)
    GOOD_HINT = re.compile(
        r"(article|content|post|entry|main|story|body|markdown|prose|readme)", re.I)
    BLOCK_TAGS = ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5",
                  "blockquote", "pre", "section", "article")

    class _Node:
        __slots__ = ("tag", "ident", "parent", "children", "parts",
                     "text_len", "link_len", "para")

        def __init__(self, tag: str, ident: str, parent) -> None:
            self.tag = tag
            self.ident = ident
            self.parent = parent
            self.children: List[Any] = []
            self.parts: List[str] = []
            self.text_len = 0
            self.link_len = 0
            self.para = 0

    def _build(self, html: str):
        from html.parser import HTMLParser

        outer = self

        class Parser(HTMLParser):
            def __init__(self) -> None:
                super().__init__(convert_charrefs=True)
                self.root = outer._Node("root", "", None)
                self.node = self.root
                self.skip_depth = 0
                self.link_depth = 0

            def handle_starttag(self, tag, attrs):
                if self.skip_depth:
                    if tag in outer.SKIP:
                        self.skip_depth += 1
                    return
                if tag in outer.SKIP:
                    self.skip_depth = 1
                    return
                if tag == "a":
                    self.link_depth += 1
                    return
                if tag in outer.BLOCK_TAGS:
                    self.node.parts.append("\n")
                if tag in outer.CANDIDATES:
                    mapping = dict(attrs)
                    ident = f"{mapping.get('class', '')} {mapping.get('id', '')} " \
                            f"{mapping.get('role', '')}"
                    child = outer._Node(tag, ident, self.node)
                    self.node.children.append(child)
                    self.node = child

            def handle_endtag(self, tag):
                if self.skip_depth:
                    if tag in outer.SKIP:
                        self.skip_depth -= 1
                    return
                if tag == "a":
                    self.link_depth = max(0, self.link_depth - 1)
                    return
                if tag == "p":
                    self.node.para += 1
                if tag in outer.CANDIDATES and self.node.parent is not None:
                    self.node = self.node.parent

            def handle_data(self, data):
                if self.skip_depth or not data.strip():
                    return
                self.node.parts.append(data)
                size = len(data.strip())
                walker = self.node
                while walker is not None:
                    walker.text_len += size
                    if self.link_depth:
                        walker.link_len += size
                    walker = walker.parent

        parser = Parser()
        with contextlib.suppress(Exception):
            parser.feed(html)
        return parser.root

    def _score(self, node) -> float:
        """Prose is long and link-poor; menus are short and link-dense."""
        if node.text_len < 120:
            return -1.0
        link_density = node.link_len / max(1, node.text_len)
        if link_density > 0.55:
            return -1.0
        score = node.text_len * (1.0 - link_density) + node.para * 25.0
        if self.BAD_HINT.search(node.ident):
            score *= 0.15
        if self.GOOD_HINT.search(node.ident):
            score *= 1.4
        if node.tag in ("article", "main"):
            score *= 1.6
        return score

    @staticmethod
    def _render(node) -> str:
        chunks: List[str] = []

        def walk(current) -> None:
            chunks.extend(current.parts)
            for child in current.children:
                walk(child)

        walk(node)
        text = "".join(chunks)
        text = re.sub(r"[ \t]+", " ", text)
        return re.sub(r"\n\s*\n\s*\n+", "\n\n", text).strip()

    def to_text(self, html: str) -> str:
        root = self._build(html)
        best, best_score = None, 0.0

        def visit(node) -> None:
            nonlocal best, best_score
            score = self._score(node)
            if score > best_score:
                best, best_score = node, score
            for child in node.children:
                visit(child)

        visit(root)
        whole = self._render(root)
        if best is None:
            return whole
        picked = self._render(best)
        # Safety net: if the "article" is a sliver of the page, the scoring was
        # probably wrong — prefer everything over silently losing the answer.
        if len(picked) < 200 and len(whole) > len(picked):
            return whole
        return picked


class _TextExtractor:
    """Minimal HTML-to-text using only the stdlib."""

    SKIP = {"script", "style", "noscript", "nav", "footer", "header", "form", "svg"}

    def __init__(self) -> None:
        from html.parser import HTMLParser

        extractor = self

        class Parser(HTMLParser):
            def __init__(self) -> None:
                super().__init__(convert_charrefs=True)
                self.depth = 0
                self.chunks: List[str] = []

            def handle_starttag(self, tag, attrs):
                if tag in extractor.SKIP:
                    self.depth += 1
                elif tag in ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4"):
                    self.chunks.append("\n")

            def handle_endtag(self, tag):
                if tag in extractor.SKIP and self.depth:
                    self.depth -= 1

            def handle_data(self, data):
                if self.depth == 0 and data.strip():
                    self.chunks.append(data)

        self._parser_class = Parser

    def to_text(self, html: str) -> str:
        parser = self._parser_class()
        with contextlib.suppress(Exception):
            parser.feed(html)
        text = "".join(parser.chunks)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
        return text.strip()


class WebTools:
    """Outbound HTTP, tightly bounded.

    Policy, in order: the network must be enabled, the host must not be
    denylisted, and the response is capped in both size and time. Only URLs
    the user or their own history supplied are ever requested — nothing here
    crawls, and none of the user's captured data is ever sent anywhere.
    """

    def __init__(self, config: Config) -> None:
        self.config = config
        self.enabled = bool(config.get("network.enabled", False))
        self.timeout = float(config.get("network.timeout_sec", 10))
        self.max_bytes = int(config.get("network.max_bytes", 1_000_000))
        self.max_redirects = int(config.get("network.max_redirects", 3))
        self.denylist = [d.lower() for d in config.get("network.domain_denylist", [])]
        self.user_agent = str(config.get("network.user_agent", f"{APP_NAME}/{VERSION}"))
        self.extractor = _TextExtractor()
        self.readable = _ReadableExtractor()
        self.fetch_log: List[Dict[str, Any]] = []
        self._log_lock = threading.Lock()
        # Remember which search engine last returned results so we try it first.
        self._last_engine: Optional[str] = None
        self._last_failures: List[str] = []

    # -- policy ------------------------------------------------------------
    def _check(self, url: str) -> str:
        if not self.enabled:
            raise NetworkDenied(
                "network access is off. Turn it on with "
                f"`{APP_NAME} config --set network.enabled=true`")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise NetworkDenied(f"refusing non-http URL: {url[:80]}")
        host = (parsed.hostname or "").lower()
        if not host:
            raise NetworkDenied(f"no host in URL: {url[:80]}")
        if any(pattern in host for pattern in self.denylist if pattern):
            raise NetworkDenied(f"{host} is on your network denylist")
        return host

    def _record(self, url: str, status: str, size: int) -> None:
        entry = {"ts": now_ts(), "url": url, "status": status, "bytes": size}
        with self._log_lock:
            self.fetch_log.append(entry)
        LOG.info("fetch %s -> %s (%s)", url, status, human_bytes(size))

    # -- raw fetch ---------------------------------------------------------
    def fetch_raw(self, url: str,
                  headers: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
        """Return (content_type, body). Follows a bounded number of redirects.

        ``headers`` are merged over the defaults. When a request is refused
        with a bot-block status (403/429/503) and it was not already made as a
        browser, it is retried once with a full browser fingerprint — content
        sites behind Cloudflare and the like reject the honest minimal client,
        which is what left research finding links it could not open.
        """
        self._check(url)
        already_browser = bool(headers and "Sec-Fetch-Mode" in headers)
        try:
            return self._fetch_follow(url, headers)
        except _HttpError as exc:
            if exc.status not in (403, 429, 503) or already_browser:
                raise MindError(str(exc)) from exc
            merged = dict(self.SEARCH_HEADERS)
            if headers:
                merged.update(headers)
            previous_ua = self.user_agent
            try:
                self.user_agent = str(
                    self.config.get("network.search_user_agent", self.SEARCH_UA))
                LOG.info("retrying %s as a browser after HTTP %s", url[:70], exc.status)
                return self._fetch_follow(url, merged)
            except _HttpError as exc2:
                raise MindError(str(exc2)) from exc2
            finally:
                self.user_agent = previous_ua

    def _fetch_follow(self, url: str,
                      headers: Optional[Dict[str, str]]) -> Tuple[str, str]:
        """One fetch with bounded redirect following. Raises _HttpError on 4xx/5xx."""
        current = url
        for _ in range(self.max_redirects + 1):
            host = self._check(current)
            parsed = urllib.parse.urlsplit(current)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            # Models hand over URLs with raw spaces and other unencoded
            # characters. Encode them rather than raising an obscure
            # "URL can't contain control characters" from http.client.
            path = urllib.parse.quote(path, safe="/?=&%+:@,;~!$'()*[]#")
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            try:
                request_headers = {
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/json,text/plain,*/*",
                    "Accept-Language": "en",
                }
                if headers:
                    request_headers.update(headers)
                conn.request("GET", path, headers=request_headers)
                response = conn.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if not location:
                        raise MindError(f"redirect without a location from {current}")
                    current = urllib.parse.urljoin(current, location)
                    continue
                if response.status >= 400:
                    self._record(current, f"http {response.status}", 0)
                    raise _HttpError(response.status, current)
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    body = body[: self.max_bytes]
                content_type = (response.getheader("Content-Type") or "").split(";")[0].strip()
                self._record(current, "ok", len(body))
                charset = "utf-8"
                header = response.getheader("Content-Type") or ""
                if "charset=" in header:
                    charset = header.split("charset=")[-1].split(";")[0].strip() or "utf-8"
                return content_type, body.decode(charset, "replace")
            except (http.client.HTTPException, OSError) as exc:
                self._record(current, f"error: {exc}", 0)
                raise MindError(f"could not fetch {current}: {exc}") from exc
            finally:
                with contextlib.suppress(Exception):
                    conn.close()
        raise MindError(f"too many redirects starting at {url}")

    # -- tools -------------------------------------------------------------
    def fetch_url(self, url: str) -> str:
        content_type, body = self.fetch_raw(url)
        if "html" not in content_type:
            return body
        # Reader-mode extraction by default: a small model's context is far
        # better spent on the article than on the site's navigation.
        if self.config.get("network.readable_extraction", True):
            with contextlib.suppress(Exception):
                text = self.readable.to_text(body)
                if text.strip():
                    return text
        return self.extractor.to_text(body)

    def wikipedia(self, title: str) -> str:
        """Plain-text article extract. The right source for plot questions."""
        search = ("https://en.wikipedia.org/w/api.php?action=query&list=search"
                  f"&srsearch={urllib.parse.quote(title)}&srlimit=1&format=json")
        _, raw = self.fetch_raw(search)
        try:
            hits = json.loads(raw).get("query", {}).get("search", [])
        except ValueError as exc:
            raise MindError("wikipedia search returned invalid JSON") from exc
        if not hits:
            return f"No Wikipedia article found for {title!r}."
        page_title = hits[0]["title"]
        extract_url = ("https://en.wikipedia.org/w/api.php?action=query&prop=extracts"
                       f"&explaintext=1&redirects=1&titles={urllib.parse.quote(page_title)}"
                       "&format=json")
        _, raw_extract = self.fetch_raw(extract_url)
        try:
            pages = json.loads(raw_extract).get("query", {}).get("pages", {})
        except ValueError as exc:
            raise MindError("wikipedia extract returned invalid JSON") from exc
        for page in pages.values():
            text = page.get("extract", "")
            if text:
                return f"# {page_title}\n\n{text}"
        return f"Wikipedia article {page_title!r} had no extractable text."

    # Search front-ends serve a challenge or a 403 to obvious bots, so search
    # requests carry a full browser fingerprint. Ordinary fetches keep the
    # honest minimal one.
    SEARCH_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                 "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
    SEARCH_HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }
    DEFAULT_ENGINES = ("duckduckgo-lite", "duckduckgo-html", "bing", "mojeek")
    # Hosts that are never a real result: the engines themselves, their
    # redirectors, and obvious ad/tracker domains.
    _ENGINE_ROOTS = ("duckduckgo.com", "duck.com", "bing.com", "mojeek.com",
                     "yandex.com", "yandex.ru", "ecosia.org", "startpage.com",
                     "brave.com")
    _JUNK_HOSTS = ("go.microsoft.com", "r.msn.com", "microsofttranslator.com",
                   "doubleclick.net", "googleadservices.com", "google.com",
                   "translate.google.com", "buttondown.email", "buttondown.com",
                   "help.duckduckgo.com", "apps.apple.com", "play.google.com")
    # Anchor text that is page chrome, never a result (matched whole, lowercased).
    _CHROME_TEXT = frozenset((
        "newsletter", "subscribe", "sign in", "log in", "login", "sign up",
        "settings", "about", "about us", "privacy", "privacy policy", "feedback",
        "help", "next", "previous", "prev", "more results", "advertise",
        "advertising", "preferences", "contact", "contact us", "terms", "home",
        "images", "videos", "news", "maps", "shopping", "all", "share", "menu"))
    # URL fragments that mark non-results (share intents, engine settings, etc.).
    _JUNK_URL_SUBSTR = ("javascript:", "mailto:", "/settings", "/preferences",
                        "/l/?kh=", "twitter.com/intent", "/sharer", "facebook.com/sharer")

    # -- engine registry ---------------------------------------------------
    def _engine_specs(self) -> Dict[str, Tuple[Callable[[str], str], Callable]]:
        """name -> (build_url, parser). A lookup table; order is decided by
        :meth:`_enabled_engines`."""
        specs: Dict[str, Tuple[Callable[[str], str], Callable]] = {
            "duckduckgo-lite": (
                lambda q: "https://lite.duckduckgo.com/lite/?q=" + urllib.parse.quote(q),
                self._parse_ddg_pairs),
            "duckduckgo-html": (
                lambda q: "https://html.duckduckgo.com/html/?q=" + urllib.parse.quote(q),
                self._parse_ddg_pairs),
            "bing": (
                lambda q: "https://www.bing.com/search?setlang=en&q=" + urllib.parse.quote(q),
                self._parse_bing),
            "mojeek": (
                lambda q: "https://www.mojeek.com/search?q=" + urllib.parse.quote(q),
                self._parse_generic),
        }
        for instance in self.config.get("network.searxng_instances", []):
            base = str(instance).rstrip("/")
            specs[f"searxng:{base}"] = (
                lambda q, b=base: f"{b}/search?format=json&q=" + urllib.parse.quote(q),
                self._parse_searxng)
        return specs

    def _enabled_engines(self) -> List[str]:
        """Engine names in the order to try them, SearXNG first, last-good hoisted.

        Defensive on purpose. A shell that strips quotes out of JSON (PowerShell
        does this) turns the configured list into a bare string; iterating that
        yields one "engine" per CHARACTER, every one unknown, and search silently
        returns nothing at all. So: accept a string, keep only engines this build
        actually has, and never hand back an empty list.
        """
        specs = self._engine_specs()
        raw = self.config.get("network.search_engines", list(self.DEFAULT_ENGINES))
        if isinstance(raw, str):
            raw = [part.strip(" []'\"") for part in raw.split(",")]
        elif not isinstance(raw, (list, tuple)):
            raw = list(self.DEFAULT_ENGINES)
        configured = [str(name).strip() for name in raw if str(name).strip()]

        instances = self.config.get("network.searxng_instances", []) or []
        if isinstance(instances, str):
            instances = [part.strip(" []'\"") for part in instances.split(",")]
        searx = [f"searxng:{str(i).rstrip('/')}" for i in instances if str(i).strip()]

        ordered = searx + [n for n in configured if not n.startswith("searxng:")]
        known = [n for n in ordered if n in specs]
        if not known:
            LOG.warning("no usable entries in network.search_engines (%r) — using defaults", raw)
            known = [n for n in self.DEFAULT_ENGINES if n in specs]
        if self._last_engine and self._last_engine in known:
            known.sort(key=lambda n: n != self._last_engine)
        return known

    def search_failure_note(self) -> str:
        """Why each engine failed on the last search, for the user-facing message.

        Without this the only clue was a generic "the backend may be blocking
        this client", which is true of about six different root causes."""
        if not self._last_failures:
            return ""
        return " Engines tried — " + "; ".join(self._last_failures[:5]) + "."

    # -- HTML parsing helpers ---------------------------------------------
    @staticmethod
    def _attr(attrs: str, name: str) -> str:
        match = re.search(rf'{name}\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        return match.group(1) if match else ""

    @staticmethod
    def _iter_anchors(body: str) -> Iterator[Tuple[str, str, str]]:
        """Yield (attrs, href, visible_text) for every <a> in the page."""
        import html as _html
        for match in re.finditer(r"<a\b([^>]*?)>(.*?)</a>", body, re.S | re.I):
            attrs, inner = match.group(1), match.group(2)
            href = re.search(r'href\s*=\s*["\']([^"\']+)["\']', attrs, re.I)
            if not href:
                continue
            text = re.sub(r"<[^>]+>", " ", inner)
            text = re.sub(r"\s+", " ", _html.unescape(text)).strip()
            yield attrs, href.group(1), text

    @staticmethod
    def _unwrap_ddg(href: str) -> str:
        if "uddg=" in href:
            return urllib.parse.unquote(href.split("uddg=")[-1].split("&")[0])
        if href.startswith("//"):
            return "https:" + href
        return href

    @staticmethod
    def _unwrap_bing(href: str) -> str:
        # Some Bing links are redirectors: /ck/a?...&u=a1<base64url>. The main
        # result title, though, is usually a direct href — so decode when it is
        # a redirector and otherwise pass the URL straight through.
        if "/ck/a" in href and "u=" in href:
            match = re.search(r"[?&]u=([^&]+)", href)
            if match:
                raw = match.group(1)
                # The payload is base64url, sometimes with an "a1" scheme prefix.
                for candidate in ((raw[2:] if raw.startswith("a1") else raw), raw):
                    with contextlib.suppress(Exception):
                        import base64
                        decoded = base64.urlsafe_b64decode(
                            candidate + "=" * (-len(candidate) % 4)).decode("utf-8", "replace")
                        if decoded.startswith("http"):
                            return decoded
        if href.startswith("//"):
            return "https:" + href
        return href

    def _parse_ddg_pairs(self, body: str, limit: int) -> List[Tuple[str, str]]:
        """DuckDuckGo lite/html: result anchors carry result-link / result__a, or
        a uddg= redirector. Direct hrefs (used by test fixtures) are kept too."""
        pairs: List[Tuple[str, str]] = []
        for attrs, href, text in self._iter_anchors(body):
            cls = self._attr(attrs, "class")
            if not ("result__a" in cls or "result-link" in cls or "uddg=" in href):
                continue
            url = self._unwrap_ddg(href)
            if url.startswith("http") and text:
                pairs.append((text, url))
            if len(pairs) >= limit:
                break
        return pairs

    _ANCHOR_RE = r'<a\b[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>'

    def _external_url(self, url: str) -> bool:
        """A real destination, not the engine's own chrome/CDN (r.bing.com etc.)."""
        if not url.lower().startswith("http"):
            return False
        host = ""
        with contextlib.suppress(ValueError):
            host = (urllib.parse.urlsplit(url).hostname or "").lower()
        return bool(host) and not self._is_junk_host(host)

    def _url_from_cite(self, shown: str) -> str:
        """Bing renders the destination as text: "https://site.com › guides › x"."""
        shown = re.split(r"[›»]", shown)[0].strip().rstrip("/").replace(" ", "")
        if not shown:
            return ""
        url = shown if shown.lower().startswith("http") else "https://" + shown
        if not re.match(r"^https?://[\w.-]+\.[a-z]{2,}", url, re.I):
            return ""
        return url if self._external_url(url) else ""

    def _parse_bing(self, body: str, limit: int) -> List[Tuple[str, str]]:
        """Resolve each `b_algo` result block independently.

        Every block is padded with r.bing.com stylesheet links and its title
        href is often an opaque /ck/a redirect, so a single global strategy
        picks up chrome, "succeeds", and starves the later fallbacks — which is
        how a page carrying ten real results parsed as zero. Instead each block
        is resolved on its own, trying the <h2> link, then any external anchor,
        then the <cite> URL Bing prints as visible text; anything pointing back
        at Bing is rejected before it can count as a result.
        """
        import html as _html

        def text_of(inner: str) -> str:
            return re.sub(r"\s+", " ", _html.unescape(re.sub(r"<[^>]+>", " ", inner))).strip()

        pairs: List[Tuple[str, str]] = []
        seen: set = set()

        def keep(url: str, title: str) -> None:
            if url and url not in seen and self._external_url(url):
                seen.add(url)
                pairs.append((title or url, url))

        for block in re.split(r'class=["\'][^"\']*\bb_algo\b[^"\']*["\']', body)[1:]:
            heading = re.search(r"<h2\b[^>]*>(.*?)</h2>", block, re.S | re.I)
            title = text_of(heading.group(1)) if heading else ""
            url = ""
            # 1. the <h2> title link
            if heading:
                for anchor in re.finditer(self._ANCHOR_RE, heading.group(1), re.S | re.I):
                    candidate = self._unwrap_bing(anchor.group(1))
                    if self._external_url(candidate):
                        url = candidate
                        break
            # 2. any external anchor in the block
            if not url:
                for anchor in re.finditer(self._ANCHOR_RE, block[:8000], re.S | re.I):
                    candidate = self._unwrap_bing(anchor.group(1))
                    if self._external_url(candidate):
                        url = candidate
                        title = title or text_of(anchor.group(2))
                        break
            # 3. the visible <cite> URL, when every href is an opaque redirect
            if not url:
                cite = re.search(r"<cite\b[^>]*>(.*?)</cite>", block, re.S | re.I)
                if cite:
                    url = self._url_from_cite(text_of(cite.group(1)))
            keep(url, title)
            if len(pairs) >= limit:
                return pairs

        # Page-wide fallbacks, only if per-block resolution found nothing at all.
        if not pairs:
            for match in re.finditer(
                    r'<a\b([^>]*?\bh=["\']ID=SERP[^"\']*["\'][^>]*?)>(.*?)</a>', body, re.S | re.I):
                href = re.search(r'href\s*=\s*["\']([^"\']+)["\']', match.group(1), re.I)
                if href:
                    keep(self._unwrap_bing(href.group(1)), text_of(match.group(2)))
                if len(pairs) >= limit:
                    break
        if not pairs:
            for match in re.finditer(r"<cite\b[^>]*>(.*?)</cite>", body, re.S | re.I):
                shown = text_of(match.group(1))
                keep(self._url_from_cite(shown), shown)
                if len(pairs) >= limit:
                    break
        return pairs

    def _parse_generic(self, body: str, limit: int) -> List[Tuple[str, str]]:
        """Engine-agnostic parser: every external anchor with real text, with
        DuckDuckGo/Bing redirectors unwrapped. This is the safety net when an
        engine's specific markup has changed out from under its parser — _clean
        strips the chrome and trackers this inevitably also picks up."""
        pairs: List[Tuple[str, str]] = []
        for _attrs, href, text in self._iter_anchors(body):
            url = self._unwrap_ddg(self._unwrap_bing(href))
            if url.startswith("//"):
                url = "https:" + url
            if not url.startswith("http") or len(text) < 3:
                continue
            pairs.append((text, url))
            if len(pairs) >= limit * 6:
                break
        return pairs

    def _parse_searxng(self, body: str, limit: int) -> List[Tuple[str, str]]:
        """SearXNG's JSON API: {"results": [{"url", "title", ...}]}."""
        try:
            data = json.loads(body)
        except ValueError:
            return []
        pairs: List[Tuple[str, str]] = []
        for item in (data.get("results", []) if isinstance(data, dict) else []):
            url = str(item.get("url", ""))
            title = str(item.get("title", "") or url)
            if url.startswith("http"):
                pairs.append((title, url))
            if len(pairs) >= limit:
                break
        return pairs

    # -- result hygiene ----------------------------------------------------
    # A challenge page announces itself in its <title> or with a very specific
    # human-verification phrase. Deliberately NOT a scan for common words like
    # "enable javascript" or "captcha" anywhere in the body — real results pages
    # carry those in <noscript>/footers, and flagging them threw away good Bing
    # and DuckDuckGo results.
    _BLOCK_TITLES = frozenset((
        "captcha", "just a moment...", "just a moment",
        "attention required! | cloudflare", "attention required!",
        "access denied", "security check", "are you human?", "robot check",
        "duckduckgo", "bing", "verifying you are human"))
    _BLOCK_PHRASES = ("verify you are human", "are you a robot",
                      "unusual traffic from your computer network",
                      "/cdn-cgi/challenge-platform", "please complete the security check",
                      "complete the captcha to", "checking if the site connection is secure")

    def _looks_like_block(self, body: str) -> bool:
        """True only for an unmistakable challenge/captcha page — matched by its
        title (a real results page titles itself with the query, e.g. 'detection
        engineering - Search', never a bare 'Bing' or 'Captcha') or a specific
        verification phrase. Keeps a blocked engine from leaking page chrome as a
        fake result without ever discarding a genuine results page."""
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip().lower() if title_match else ""
        if title in self._BLOCK_TITLES:
            return True
        low = body.lower()
        return any(phrase in low for phrase in self._BLOCK_PHRASES)

    def _is_junk_host(self, host: str) -> bool:
        host = host.lower()
        if any(host == root or host.endswith("." + root) for root in self._ENGINE_ROOTS):
            return True
        return host in self._JUNK_HOSTS

    def _clean(self, pairs: List[Tuple[str, str]], limit: int) -> List[Tuple[str, str]]:
        """Drop non-http links, engine/tracker hosts, page chrome and duplicates."""
        out: List[Tuple[str, str]] = []
        seen: set = set()
        for title, url in pairs:
            if url.startswith("//"):
                url = "https:" + url
            if not url.lower().startswith("http"):
                continue
            low = url.lower()
            if any(bit in low for bit in self._JUNK_URL_SUBSTR):
                continue
            if (title or "").strip().lower() in self._CHROME_TEXT:
                continue
            host = ""
            with contextlib.suppress(ValueError):
                host = (urllib.parse.urlsplit(url).hostname or "").lower()
            if not host or self._is_junk_host(host):
                continue
            key = url.split("#")[0]
            if key in seen:
                continue
            seen.add(key)
            out.append(((title or url).strip(), key))
            if len(out) >= limit:
                break
        return out

    def _run_engine(self, name: str, query: str, limit: int) -> List[Tuple[str, str]]:
        """Fetch and parse one engine. Raises MindError if the fetch fails.

        If the engine's specific parser finds nothing — usually because the
        engine changed its markup — the engine-agnostic parser is tried on the
        same page before giving up, so a class-name change degrades to slightly
        noisier results instead of zero.
        """
        specs = self._engine_specs()
        if name not in specs:
            raise MindError(f"unknown search engine {name!r}")
        build_url, parse = specs[name]
        previous_ua = self.user_agent
        try:
            self.user_agent = str(self.config.get("network.search_user_agent", self.SEARCH_UA))
            _, body = self.fetch_raw(build_url(query), headers=self.SEARCH_HEADERS)
        finally:
            self.user_agent = previous_ua
        # A challenge/captcha page must never fall through to the generic parser,
        # which would scrape its chrome (nav, newsletter link) as fake results.
        if parse is not self._parse_searxng and self._looks_like_block(body):
            LOG.info("search engine %r served a challenge/near-empty page for %r",
                     name, query[:50])
            return []
        want = max(limit * 2, limit)
        pairs = parse(body, want)
        cleaned = self._clean(pairs, limit)
        if not cleaned and parse is not self._parse_generic and parse is not self._parse_searxng:
            cleaned = self._clean(self._parse_generic(body, want), limit)
        return cleaned

    def _wikipedia_search(self, query: str, limit: int) -> List[str]:
        """Stable JSON fallback when every search engine is blocked."""
        url = ("https://en.wikipedia.org/w/api.php?action=opensearch&limit="
               f"{limit}&format=json&search={urllib.parse.quote(query)}")
        _, raw = self.fetch_raw(url)
        try:
            payload = json.loads(raw)
        except ValueError:
            return []
        titles = payload[1] if len(payload) > 1 else []
        links = payload[3] if len(payload) > 3 else []
        return [f"{title} — {link}" for title, link in zip(titles, links)]

    def search_links(self, query: str, limit: int = 5) -> List[Tuple[str, str]]:
        """Search real web engines and return [(title, url)].

        Each engine is tried in turn until one yields results; a blocked or
        unparseable engine is skipped, never fatal. Returns [] only when every
        engine failed — callers decide whether to fall back to Wikipedia. This
        replaces the old single-DuckDuckGo path that collapsed to Wikipedia the
        moment DuckDuckGo served a challenge.
        """
        if not self.config.get("network.allow_search", True):
            return []
        failures: List[str] = []
        for name in self._enabled_engines():
            try:
                pairs = self._run_engine(name, query, limit)
            except MindError as exc:
                failures.append(f"{name}: {exc}")
                continue
            if pairs:
                self._last_engine = name
                LOG.info("search %r via %s -> %d result(s)", query[:60], name, len(pairs))
                return pairs
            failures.append(f"{name}: no results parsed")
        self._last_failures = failures
        LOG.warning("all search engines failed for %r -> %s", query[:60], "; ".join(failures[:8]))
        return []

    def web_search(self, query: str, limit: int = 5) -> str:
        if not self.config.get("network.allow_search", True):
            raise NetworkDenied("web search is disabled in config")
        pairs = self.search_links(query, limit)
        if pairs:
            return "\n".join(f"{title} — {url}" for title, url in pairs)
        # Every engine was blocked or unparseable on this network; the
        # encyclopedia API is a different host and usually still answers.
        wiki: List[str] = []
        with contextlib.suppress(MindError):
            wiki = self._wikipedia_search(query, limit)
        if wiki:
            return ("(web search engines were unreachable — these are Wikipedia matches)\n"
                    + "\n".join(wiki))
        return (f"No results for {query!r}. Every search engine this build knows was blocked or "
                f"unparseable on this network, and Wikipedia found nothing. Run "
                f"`{APP_NAME} netcheck` to see which engines your network allows.")

    def _choose_sources(self, candidates: List[Tuple[str, str]], max_sources: int,
                        seen_domains: set) -> List[Tuple[str, str]]:
        """Pick one page per domain, honouring the denylist and domains already used.

        ``seen_domains`` is mutated so a multi-round investigation never opens
        two pages from the same site across its rounds.
        """
        chosen: List[Tuple[str, str]] = []
        for title, url in candidates:
            host = ""
            with contextlib.suppress(ValueError):
                host = (urllib.parse.urlsplit(url).hostname or "").lower()
            if not host or host in seen_domains:
                continue
            if any(pattern in host for pattern in self.denylist if pattern):
                continue
            seen_domains.add(host)
            chosen.append((title, url))
            if len(chosen) >= max_sources:
                break
        return chosen

    def _fetch_sources(self, chosen: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
        """Fetch the chosen pages in parallel. A failure becomes an inline note,
        never an exception — one dead link must not sink the whole digest."""
        if not chosen:
            return []
        import concurrent.futures

        def grab(item: Tuple[str, str]) -> Tuple[str, str, str]:
            title, url = item
            try:
                return title, url, self.fetch_url(url)
            except MindError as exc:
                return title, url, f"[could not fetch: {exc}]"

        results: List[Tuple[str, str, str]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(chosen))) as pool:
            for outcome in pool.map(grab, chosen):
                results.append(outcome)
        return results

    @staticmethod
    def _is_readable(text: str) -> bool:
        """A fetched page counts as usable only if it returned real body text —
        not a fetch error and not a near-empty JS shell."""
        return not text.startswith("[could not fetch") and len(text.strip()) >= 200

    def _fetch_readable(self, candidates: List[Tuple[str, str]], max_sources: int,
                        seen_domains: set) -> List[Tuple[str, str, str]]:
        """Choose a few more sources than needed, fetch them, and keep the ones
        that actually read. Falls back to whatever came back (errors included, so
        the header stays honest) only when nothing was readable."""
        extra = max(0, int(self.config.get("network.source_overfetch", 3)))
        chosen = self._choose_sources(candidates, max_sources + extra, seen_domains)
        results = self._fetch_sources(chosen)
        readable = [row for row in results if self._is_readable(row[2])]
        if readable:
            return readable[:max_sources]
        return results[:max_sources]

    def _format_sources(self, query: str, results: List[Tuple[str, str, str]],
                        per_source_chars: int = 2500, round_note: str = "") -> str:
        """Render fetched sources into a cited digest with continuous numbering.

        The block shape (``[n] title`` / four-space-indented url / body) is
        load-bearing: the knowledge cache extracts source URLs from it, so it
        must not drift.
        """
        if not results:
            return (f"No search results for {query!r}. The search backend may be blocking "
                    f"this client; try the wikipedia tool for encyclopedic topics.")
        blocks: List[str] = []
        usable = 0
        for index, (title, url, text) in enumerate(results, start=1):
            body = re.sub(r"\n{3,}", "\n\n", text).strip()
            if not body.startswith("[could not fetch"):
                usable += 1
            if len(body) > per_source_chars:
                body = body[:per_source_chars] + " […]"
            blocks.append(f"[{index}] {title}\n    {url}\n{body}")
        header = (f"Researched {query!r}{round_note}: opened {usable} of {len(results)} "
                  f"source(s). Cite them as [1], [2] etc.\n")
        if usable == 0:
            header = (f"Found {len(results)} result(s) for {query!r} but could not read any of "
                      f"them. Report that rather than guessing.\n")
        return header + "\n\n".join(blocks)

    def research(self, query: str, max_sources: int = 3, per_source_chars: int = 2500) -> str:
        """Search, open the top results, and return a cited digest.

        This is the whole research loop in one call. Left to itself a small
        model tends to run the search, see a list of titles, and answer from
        those alone — so the fetching and reading happen here in Python rather
        than depending on the model to chain four tool calls correctly.

        One pass, one query. :class:`DeepResearcher` layers gap-driven follow-up
        rounds on top of these same helpers.
        """
        candidates = self.search_links(query, limit=max(max_sources * 4, 10))
        if not candidates:
            return self._no_engine_digest(query, max_sources, per_source_chars)
        # One page per domain, over-provisioned so dead links don't zero it out.
        results = self._fetch_readable(candidates, max_sources, set())
        return self._format_sources(query, results, per_source_chars)

    def _no_engine_digest(self, query: str, max_sources: int, per_source_chars: int) -> str:
        """Every engine failed. Say exactly why, and still try Wikipedia rather
        than handing the model an empty result it can only apologise for."""
        wiki_pairs: List[Tuple[str, str]] = []
        with contextlib.suppress(MindError):
            for line in self._wikipedia_search(query, 3):
                title, _, link = line.rpartition(" — ")
                if link.strip().startswith("http"):
                    wiki_pairs.append((title.strip(), link.strip()))
        if wiki_pairs:
            results = self._fetch_readable(wiki_pairs, max_sources, set())
            if results:
                return ("(no web search engine was usable, so these are Wikipedia sources —"
                        " say so if they do not cover the question)\n"
                        + self._format_sources(query, results, per_source_chars))
        return (f"No search results for {query!r}.{self.search_failure_note()} "
                f"Run `{APP_NAME} websearch \"{query[:40]}\"` to see which engines this "
                f"network allows.")

    def youtube_transcript(self, url: str) -> str:
        """Captions for a video, falling back to the page description."""
        _, page = self.fetch_raw(url)
        tracks = re.search(r'"captionTracks":(\[.*?\])', page)
        if tracks:
            with contextlib.suppress(ValueError, KeyError, IndexError):
                entries = json.loads(tracks.group(1).replace("\\u0026", "&"))
                base = entries[0]["baseUrl"].replace("\\u0026", "&")
                _, xml = self.fetch_raw(base)
                lines = re.findall(r"<text[^>]*>(.*?)</text>", xml, re.S)
                if lines:
                    import html as html_module

                    text = " ".join(html_module.unescape(re.sub(r"<[^>]+>", "", line))
                                    for line in lines)
                    return re.sub(r"\s+", " ", text).strip()
        description = re.search(r'"shortDescription":"(.*?)","', page)
        if description:
            return description.group(1).encode().decode("unicode_escape", "replace")
        return "No captions or description could be extracted from that video page."


# ==========================================================================
# Deep research — gap-driven, multi-round investigation
# ==========================================================================

DEEP_GAP_PROMPT = """You are directing a web research process. The goal is to answer:

QUESTION: {question}

Evidence gathered so far, from the open web:
{evidence}

Judge whether this evidence is enough to answer the QUESTION well and specifically.
- If it is, or if more searching is unlikely to help, reply exactly:
  {{"sufficient": true, "followups": []}}
- If it is not, propose 1 to {max_followups} NEW web-search queries that would fill the \
gaps. Each query must target a concrete missing fact and must not repeat what the evidence \
already covers. Reply:
  {{"sufficient": false, "followups": ["first query", "second query"]}}

Reply with ONLY the JSON object and nothing else."""


class DeepResearcher:
    """Multi-round web investigation layered over :class:`WebTools`.

    A single search-and-read pass often answers a neighbouring question, or
    only half of the one asked. A capable researcher notices that and searches
    again with a sharper query. Small local models rarely do this unprompted,
    so the loop lives here in Python and the model is asked exactly one narrow
    thing per round — "is this enough, and if not, what should I search next?"
    — which is the kind of bounded decision small models make reliably.

    Every axis is bounded: a round budget, a per-round follow-up budget, a hard
    cap on total pages opened, one page per domain across the whole
    investigation, and no query run twice. The output is a single cited digest
    with continuous numbering, byte-compatible with :meth:`WebTools.research`,
    so it drops into every consumer that already reads a research digest.
    """

    def __init__(self, config: Config, web: WebTools, client: OllamaClient,
                 model: str) -> None:
        self.config = config
        self.web = web
        self.client = client
        self.model = model

    def _enabled(self) -> bool:
        return bool(self.config.get("knowledge.deep_research", True))

    @staticmethod
    def _norm_query(query: str) -> str:
        return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", query.lower())).strip()

    @staticmethod
    def _parse_gap(text: str) -> Tuple[bool, List[str]]:
        """Tolerantly extract {"sufficient": bool, "followups": [...]}.

        Defaults to (sufficient=True, no followups) on any doubt, so a garbled
        model reply ends the investigation cleanly rather than looping.
        """
        if not text:
            return True, []
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
        candidate = fenced.group(1) if fenced else None
        if candidate is None:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end <= start:
                return True, []
            candidate = text[start:end + 1]
        candidate = re.sub(r",\s*([\]}])", r"\1", candidate)  # trailing commas
        try:
            data = json.loads(candidate)
        except ValueError:
            return True, []
        if not isinstance(data, dict):
            return True, []
        sufficient = bool(data.get("sufficient", True))
        raw = data.get("followups") or []
        if not isinstance(raw, list):
            return sufficient, []
        followups = [str(item).strip() for item in raw
                     if isinstance(item, str) and str(item).strip()]
        return sufficient, followups

    def _gap_check(self, question: str, results: List[Tuple[str, str, str]],
                   max_followups: int) -> Tuple[bool, List[str]]:
        """One focused model call: does the evidence answer the question yet?"""
        # Keep the gap prompt small — a compact view of the evidence is enough
        # to decide what is still missing.
        evidence = self.web._format_sources(question, results, per_source_chars=700)
        prompt = DEEP_GAP_PROMPT.format(question=question, evidence=evidence[:6000],
                                        max_followups=max_followups)
        options = {"temperature": 0.1,
                   "num_ctx": int(self.config.get("runtime.num_ctx", 8192))}
        try:
            raw = self.client.chat(self.model, [{"role": "user", "content": prompt}], options)
        except (OllamaError, MindError):
            return True, []  # can't reason about gaps -> stop, answer with what we have
        return self._parse_gap(raw)

    def investigate(self, query: str, max_sources: Optional[int] = None,
                    per_source_chars: int = 2500,
                    on_round: Optional[Callable[[int, str], None]] = None) -> str:
        """Search, read, find the gap, search again. Returns a cited digest.

        Never raises: a research aid must degrade to "here is what I could
        find" rather than crashing the answer.
        """
        web = self.web
        if max_sources is None:
            max_sources = int(self.config.get("knowledge.max_sources", 3))
        max_rounds = max(0, int(self.config.get("knowledge.max_rounds", 2)))
        max_followups = max(1, int(self.config.get("knowledge.deep_max_followups", 2)))
        total_cap = max(max_sources, int(self.config.get("knowledge.deep_max_total_sources", 8)))

        seen_domains: set = set()
        tried: set = {self._norm_query(query)}
        results: List[Tuple[str, str, str]] = []

        # Round 1: the question as asked.
        candidates = web.search_links(query, limit=max(max_sources * 4, 10))
        if not candidates:
            return web._no_engine_digest(query, max_sources, per_source_chars)
        results.extend(web._fetch_readable(candidates, max_sources, seen_domains))
        rounds_done = 1

        if self._enabled():
            for _ in range(max_rounds):
                if len(results) >= total_cap:
                    break
                sufficient, followups = self._gap_check(query, results, max_followups)
                if sufficient or not followups:
                    break
                progressed = False
                for followup in followups[:max_followups]:
                    key = self._norm_query(followup)
                    if not key or key in tried:
                        continue
                    tried.add(key)
                    if on_round:
                        with contextlib.suppress(Exception):
                            on_round(rounds_done + 1, followup)
                    cand = web.search_links(followup, limit=max(max_sources * 4, 10))
                    fresh = web._fetch_readable(cand, max_sources, seen_domains)
                    if fresh:
                        results.extend(fresh)
                        progressed = True
                    if len(results) >= total_cap:
                        break
                if not progressed:  # nothing new to add; stop rather than spin
                    break
                rounds_done += 1

        results = results[:total_cap]
        note = "" if rounds_done <= 1 else f" over {rounds_done} search rounds"
        # Share a fixed character budget across however many sources were
        # opened, so a deep investigation stays within the model's context
        # window instead of dropping the system prompt off the front.
        if results:
            budget = int(self.config.get("knowledge.deep_digest_chars", 9000))
            per_source_chars = max(600, min(per_source_chars, budget // len(results)))
        return web._format_sources(query, results, per_source_chars, round_note=note)


# ==========================================================================
# Agent tools
# ==========================================================================

class ToolBox:
    """The functions the model may call.

    Everything deterministic — date arithmetic, filtering, ranking — happens
    here in Python. The model's only job is deciding which tool to call with
    what arguments, which is the part small models can actually do reliably.
    """

    def __init__(self, config: Config, store: Store, retriever: Optional[Retriever],
                 web: WebTools, knowledge: Optional["KnowledgeCache"] = None,
                 researcher: Optional["DeepResearcher"] = None) -> None:
        self.config = config
        self.store = store
        self.retriever = retriever
        self.web = web
        self.knowledge = knowledge
        self.researcher = researcher
        self.calls: List[Dict[str, Any]] = []

    # -- schema ------------------------------------------------------------
    def schema(self) -> List[dict]:
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "resolve_time",
                    "description": ("Convert a natural-language time expression such as "
                                    "'tuesday around 5pm', 'yesterday', or 'last week' into an "
                                    "absolute time range. ALWAYS use this before asking about a "
                                    "time period; never compute dates yourself."),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "expression": {"type": "string",
                                           "description": "e.g. 'tuesday around 5pm'"}},
                        "required": ["expression"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "timeline",
                    "description": ("List everything captured in a time range, oldest first: "
                                    "apps focused, pages visited, things copied. Use this to "
                                    "answer 'what was I doing/watching/reading at <time>'."),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "start": {"type": "string", "description": "ISO datetime or unix ts"},
                            "end": {"type": "string", "description": "ISO datetime or unix ts"},
                            "limit": {"type": "integer", "description": "max rows (default 40)"},
                        },
                        "required": ["start", "end"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "app_usage",
                    "description": ("How long the user spent in each app or game over a time "
                                    "range, longest first. Use for 'what did I use most', "
                                    "'how long was I playing/in <app>', screen-time questions."),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                        },
                        "required": ["start", "end"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_memory",
                    "description": ("Search the user's captured history by meaning and keywords. "
                                    "Optionally restrict to a time range or a source "
                                    "(clipboard, focus, browser, file)."),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                            "source": {"type": "string"},
                            "limit": {"type": "integer"},
                        },
                        "required": ["query"],
                    },
                },
            },
        ]
        if self.web.enabled:
            tools.extend([
                {
                    "type": "function",
                    "function": {
                        "name": "wikipedia",
                        "description": ("Look up a Wikipedia article as plain text. Best source "
                                        "for a film/show/book plot, facts about a topic, or "
                                        "current events — a year like '2026' is a valid "
                                        "title and lists that year's major events."),
                        "parameters": {
                            "type": "object",
                            "properties": {"title": {"type": "string"}},
                            "required": ["title"],
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "fetch_url",
                        "description": ("Fetch a web page and return its readable text. Use for "
                                        "a specific URL found in the user's history."),
                        "parameters": {
                            "type": "object",
                            "properties": {"url": {"type": "string"}},
                            "required": ["url"],
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "research",
                        "description": ("Investigate a question on the open web: search, open "
                                        "the top results, and — if they don't fully answer it — "
                                        "search again to fill the gaps, returning the combined "
                                        "text with numbered citations. USE THIS FIRST for any "
                                        "open question about the world. Prefer it over web_search."),
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "query": {"type": "string"},
                                "max_sources": {"type": "integer",
                                                "description": "pages to open (default 3)"},
                            },
                            "required": ["query"],
                        },
                    },
                },
            ])
        return tools

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _to_ts(value: Any) -> Optional[float]:
        if value is None or value == "":
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip().replace("Z", "")
        with contextlib.suppress(ValueError):
            return float(text)
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M",
                    "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            with contextlib.suppress(ValueError):
                return datetime.strptime(text, fmt).timestamp()
        return None

    # -- dispatch ----------------------------------------------------------
    def call(self, name: str, arguments: Dict[str, Any]) -> str:
        started = time.time()
        try:
            result = self._dispatch(name, arguments)
            status = "ok"
        except (MindError, OllamaError) as exc:
            result = f"ERROR: {exc}"
            status = "error"
        except Exception as exc:  # a tool must never kill the loop
            result = f"ERROR: {type(exc).__name__}: {exc}"
            status = "error"
        budget = int(self.config.get("agent.tool_result_chars", 4000))
        if len(result) > budget:
            result = result[:budget] + f"\n[truncated at {budget} characters]"
        self.calls.append({
            "tool": name, "arguments": arguments, "status": status,
            "ms": int((time.time() - started) * 1000), "chars": len(result),
        })
        return result

    def _dispatch(self, name: str, args: Dict[str, Any]) -> str:
        if name == "resolve_time":
            expression = str(args.get("expression", ""))
            resolved = resolve_time_expression(expression)
            if not resolved:
                return (f"Could not interpret {expression!r}. Try a weekday, 'yesterday', "
                        f"'last week', or an explicit date like 2026-09-02.")
            start, end, description = resolved
            return json.dumps({
                "start": datetime.fromtimestamp(start).isoformat(timespec="minutes"),
                "end": datetime.fromtimestamp(end).isoformat(timespec="minutes"),
                "description": description,
            })

        if name == "timeline":
            start = self._to_ts(args.get("start"))
            end = self._to_ts(args.get("end"))
            if start is None or end is None:
                return "ERROR: start and end are required; call resolve_time first."
            limit = int(args.get("limit") or 40)
            rows = self.store.in_range(start, end, limit=limit)
            if not rows:
                window = (f"{datetime.fromtimestamp(start):%A %Y-%m-%d %H:%M} to "
                          f"{datetime.fromtimestamp(end):%H:%M}")
                return (f"NOTHING CAPTURED between {window}. The user's machine recorded no "
                        f"activity then — say so plainly rather than guessing.")
            lines = []
            for row in rows:
                meta = json.loads(row["meta"] or "{}")
                duration = meta.get("duration_sec")
                stamp = datetime.fromtimestamp(row["ts"]).strftime("%H:%M")
                entry = f"{stamp} [{row['source']}] {row['text'][:200]}"
                if duration:
                    entry += f" ({int(duration)}s)"
                if row["source"] == "browser" and row["origin"]:
                    entry += f" <{row['origin']}>"
                lines.append(entry)
            header = f"{len(rows)} entries on {datetime.fromtimestamp(start):%A %Y-%m-%d}:"
            return header + "\n" + "\n".join(lines)

        if name == "app_usage":
            start = self._to_ts(args.get("start"))
            end = self._to_ts(args.get("end"))
            if start is None or end is None:
                return "ERROR: start and end are required; call resolve_time first."
            rows = self.store.app_usage(start, end, limit=20)
            if not rows:
                return ("NOTHING CAPTURED between those times. No app/window activity was "
                        "recorded — say so rather than guessing.")
            lines = []
            for entry in rows:
                mins = entry["seconds"] / 60.0
                lines.append(f"{entry['app']}: {mins:.0f} min across {entry['sessions']} session(s)")
            return "App usage (longest first):\n" + "\n".join(lines)
        if name == "search_memory":
            if self.retriever is None:
                return "ERROR: memory search is unavailable."
            query = str(args.get("query", ""))
            start = self._to_ts(args.get("start"))
            end = self._to_ts(args.get("end"))
            limit = int(args.get("limit") or 8)
            hits = self.retriever.retrieve(query, days=None, top_k=limit)
            source = args.get("source")
            filtered = []
            for hit in hits:
                if source and hit.source != source:
                    continue
                if start is not None and hit.ts < start:
                    continue
                if end is not None and hit.ts > end:
                    continue
                filtered.append(hit)
            if not filtered:
                return f"No memories matched {query!r} with those filters."
            return "\n".join(f"[{hit.label()}] {hit.text[:300]}" for hit in filtered)

        if name == "wikipedia":
            return self.web.wikipedia(str(args.get("title", "")))
        if name == "fetch_url":
            url = str(args.get("url", ""))
            if "youtube.com/watch" in url or "youtu.be/" in url:
                return self.web.youtube_transcript(url)
            return self.web.fetch_url(url)
        if name == "research":
            query = str(args.get("query", ""))
            sources = int(args.get("max_sources") or 3)
            if self.knowledge is not None:
                # The cache path already routes through the deep researcher.
                answer = self.knowledge.lookup(query, max_sources=sources)
                if answer is not None:
                    prefix = (f"(cached, fetched {answer.age_phrase()})\n"
                              if answer.from_cache else "")
                    return prefix + answer.answer
            if self.researcher is not None and self.config.get("knowledge.deep_research", True):
                return self.researcher.investigate(query, max_sources=sources)
            return self.web.research(query, max_sources=sources)
        if name == "web_search":
            return self.web.web_search(str(args.get("query", "")))
        return f"ERROR: unknown tool {name!r}"


AGENT_SYSTEM_PROMPT = """You are {app}, a personal assistant running entirely on the user's \
own machine. Today is {weekday} {date}, local time {time}.

You have tools that read the user's own captured history (what they focused on, copied, \
browsed) and, when enabled, fetch public web pages.

How to work:
1. For any question about a time ("tuesday around 5pm", "yesterday"), call resolve_time FIRST \
to convert it, then timeline with that range. Never do calendar arithmetic yourself.
2. For "what was I watching/reading/doing", use timeline — not search_memory. Time questions \
are range lookups, not similarity searches.
3. Once you know what the user was watching or reading, you may look it up with wikipedia \
(best for plots and facts) or fetch_url (for a specific page from their history).
4. Then answer the actual question asked, citing what came from their history versus what \
came from the web.

Hard rules:
- If a tool says nothing was captured, SAY SO. Never fill the gap with something you happen \
to know about the topic — an answer about the wrong evening is worse than no answer.
- Never invent URLs, timestamps, or captures.
- YOUR TRAINING DATA IS OUT OF DATE. It ends well before today's date shown above. For any \
question about real-world events, dates, prices, releases, who currently holds a role, or \
anything that could have changed, you MUST verify with wikipedia or web_search before \
answering. Answering such a question from memory alone is a failure even if you feel certain.
- Wikipedia has an article for each year (title "2026", "2025") listing that year's major \
events — use it for "what happened in <year>" questions.
- A RESEARCH block may already have been fetched for you before you were asked. If it is \
present, use it and cite its sources; you do not need to research the same thing again.
- To look something up on the open web, call research: it searches, opens the top pages and \
returns their text with numbered citations, all in one step. Do not run web_search and then \
answer from the titles — titles are not evidence.
- If a fact could not be verified with a tool, label it plainly as unverified recall rather \
than stating it as fact.
- ANSWER THE QUESTION with what the tools and RESEARCH block give you. If the user asks for \
"the best X" or a list, extract the actual items from the sources and list them with \
citations. NEVER reply "I don't have that" or "check the official site / a tier list \
yourself" when a RESEARCH block or the research tool is available — using them and giving \
the specifics IS your job; deflecting back to the user is a failure.
- The RESEARCH block and tool results are the WEB, not the user's clipboard or history. Do \
not describe web findings as "captured" or say they are missing from their files — just \
answer from them.
- Stop calling tools once you can answer. Be concise."""


@dataclass
class AgentResult:
    answer: str
    steps: List[Dict[str, Any]]
    fell_back: bool = False


class Agent:
    """Tool-calling loop over a local model, with a hard step budget."""

    def __init__(self, config: Config, client: OllamaClient, tools: ToolBox,
                 model: str, knowledge: Optional["KnowledgeCache"] = None,
                 profile: Optional["ProfileStore"] = None) -> None:
        self.config = config
        self.client = client
        self.tools = tools
        self.model = model
        self.max_steps = int(config.get("agent.max_steps", 6))
        self.knowledge = knowledge
        self.gate = knowledge.gate if knowledge else None
        self.profile = profile
        self.prefetched: Optional["CachedAnswer"] = None

    def _profile_message(self) -> Optional[dict]:
        """The durable-profile block, if enabled and non-empty."""
        if self.profile is None or not self.config.get("profile.inject", True):
            return None
        block = self.profile.render(int(self.config.get("profile.inject_chars", 900)))
        if not block:
            return None
        return {"role": "system", "content": (
            "PROFILE — durable background about the user, distilled from their own activity. "
            "It may be imperfect or out of date; prefer the user's explicit words and fresh "
            "tool results over it, and never state it back as if they told you just now.\n"
            + block)}

    def _system_prompt(self) -> str:
        now = datetime.now()
        return AGENT_SYSTEM_PROMPT.format(
            app=APP_NAME, weekday=now.strftime("%A"),
            date=now.strftime("%Y-%m-%d"), time=now.strftime("%H:%M"))

    def run(self, question: str, history: Optional[List[dict]] = None,
            on_step: Optional[Callable[[str, dict], None]] = None) -> AgentResult:
        messages: List[dict] = [{"role": "system", "content": self._system_prompt()}]
        profile_msg = self._profile_message()
        if profile_msg:
            messages.append(profile_msg)

        # Pre-flight: if this is a question about the world rather than the
        # user's own history, look it up BEFORE the model gets a turn. Asking
        # the model to decide is exactly where it fails — it answers from
        # stale training data with total confidence.
        self.prefetched = None
        if self.knowledge is not None and self.config.get("knowledge.auto_research", True):
            query = self.gate.needs_research(question) if self.gate else None
            if query:
                answer = self.knowledge.lookup(
                    query, max_sources=int(self.config.get("knowledge.max_sources", 3)))
                if answer is not None and answer.answer:
                    self.prefetched = answer
                    freshness = ("from cache, fetched " + answer.age_phrase()
                                 if answer.from_cache else "fetched just now")
                    messages.append({"role": "system", "content": (
                        f"RESEARCH ({freshness}) for {query!r}. Your training data is older "
                        f"than this — prefer it over recall, and cite its numbered sources:\n"
                        f"{answer.answer}")})

        if history:
            messages.extend(history[-6:])
        messages.append({"role": "user", "content": question})
        options = {"num_ctx": int(self.config.get("runtime.num_ctx", 8192))}
        schema = self.tools.schema()

        for _ in range(self.max_steps):
            try:
                reply = self.client.chat_with_tools(self.model, messages, schema, options)
            except OllamaError as exc:
                # Model or server cannot do tool calling: caller falls back.
                raise ToolsUnsupported(str(exc)) from exc

            tool_calls = reply.get("tool_calls") or []
            content = (reply.get("content") or "").strip()
            if not tool_calls:
                return AgentResult(answer=content, steps=self.tools.calls)

            messages.append({"role": "assistant", "content": content,
                             "tool_calls": tool_calls})
            for call in tool_calls:
                function = call.get("function", {})
                name = function.get("name", "")
                arguments = function.get("arguments", {})
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except ValueError:
                        arguments = {"_raw": arguments}
                result = self.tools.call(name, arguments)
                if on_step:
                    on_step(name, {"arguments": arguments, "result": result})
                messages.append({"role": "tool", "content": result, "name": name})

        # Budget exhausted: ask for a final answer with what it has.
        messages.append({"role": "user", "content":
                         "Stop using tools now and answer with what you have. If the history "
                         "did not contain the answer, say so plainly."})
        final = self.client.chat(self.model, messages, options)
        return AgentResult(answer=final, steps=self.tools.calls)

    # Which phase label to show while a given tool runs.
    _TOOL_PHASE = {
        "research": "gathering from the web", "web_search": "searching the web",
        "fetch_url": "reading the page", "wikipedia": "reading Wikipedia",
        "timeline": "searching your history", "search_memory": "searching your memory",
        "app_usage": "checking app usage", "resolve_time": "working out the dates",
    }

    def run_streamed(self, question: str, history: Optional[List[dict]] = None,
                     on_text: Optional[Callable[[str], None]] = None,
                     on_phase: Optional[Callable[[str], None]] = None,
                     on_step: Optional[Callable[[str, dict], None]] = None) -> AgentResult:
        """Same loop as run(), but streams the final answer and reports phases.

        The tool-deciding turns cannot stream (the model emits the whole call
        at once), so those show a phase label; only the final answer, which is
        the part the user reads, streams token by token.
        """
        def phase(label: str) -> None:
            if on_phase:
                on_phase(label)

        messages: List[dict] = [{"role": "system", "content": self._system_prompt()}]
        profile_msg = self._profile_message()
        if profile_msg:
            messages.append(profile_msg)
        self.prefetched = None
        if self.knowledge is not None and self.config.get("knowledge.auto_research", True):
            query = self.gate.needs_research(question) if self.gate else None
            if query:
                phase("gathering from the web")
                answer = self.knowledge.lookup(
                    query, max_sources=int(self.config.get("knowledge.max_sources", 3)),
                    on_round=lambda _i, followup: phase(f"digging deeper: {followup[:48]}"))
                if answer is not None and answer.answer:
                    self.prefetched = answer
                    freshness = ("from cache, fetched " + answer.age_phrase()
                                 if answer.from_cache else "fetched just now")
                    messages.append({"role": "system", "content": (
                        f"RESEARCH ({freshness}) for {query!r}. Your training data is older "
                        f"than this — prefer it over recall, and cite its numbered sources:\n"
                        f"{answer.answer}")})
        if history:
            messages.extend(history[-6:])
        messages.append({"role": "user", "content": question})
        options = {"num_ctx": int(self.config.get("runtime.num_ctx", 8192))}
        schema = self.tools.schema()

        streamed_any = False
        for _ in range(self.max_steps):
            phase("thinking")
            content = ""
            tool_calls: List[dict] = []
            try:
                for kind, data in self.client.chat_with_tools_stream(
                        self.model, messages, schema, options):
                    if kind == "text":
                        if on_text:
                            on_text(data)
                            streamed_any = True
                    else:  # "done"
                        content = data["content"]
                        tool_calls = data["tool_calls"]
            except OllamaError as exc:
                raise ToolsUnsupported(str(exc)) from exc

            if not tool_calls:
                # The final answer already streamed through on_text above.
                return AgentResult(answer=content.strip(), steps=self.tools.calls)

            messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})
            for call in tool_calls:
                function = call.get("function", {})
                name = function.get("name", "")
                phase(self._TOOL_PHASE.get(name, f"running {name}"))
                arguments = function.get("arguments", {})
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except ValueError:
                        arguments = {"_raw": arguments}
                result = self.tools.call(name, arguments)
                if on_step:
                    on_step(name, {"arguments": arguments, "result": result})
                messages.append({"role": "tool", "content": result, "name": name})

        # Budget exhausted: stream a final synthesis.
        phase("thinking")
        messages.append({"role": "user", "content":
                         "Stop using tools now and answer with what you have. If the history "
                         "did not contain the answer, say so plainly."})
        parts: List[str] = []
        for piece in self.client.chat_stream(self.model, messages, options):
            parts.append(piece)
            if on_text:
                on_text(piece)
                streamed_any = True
        answer = "".join(parts)
        if not streamed_any and on_text:
            on_text(answer)
        return AgentResult(answer=answer.strip(), steps=self.tools.calls)


class ToolsUnsupported(MindError):
    """The model or server refused tool calling; fall back to plain retrieval."""


# ==========================================================================
# Knowledge gap detection and caching
# ==========================================================================

class KnowledgeGate:
    """Decides, in Python, whether a question needs the open web.

    Left to itself a small model skips verification when it feels confident,
    which is exactly when it is most likely to be wrong about a fact that
    changed after its training cutoff. So the decision is made here, before
    the model gets a turn, and the evidence is handed to it as context.

    The gate deliberately stays OUT of the way for questions about the user's
    own history — those are answered from captured memory, and searching the
    web for "what was I watching" would be both useless and a privacy leak.
    """

    # Things whose answer changes: never trust recall for these.
    VOLATILE = (
        "latest", "current", "currently", "right now", "today", "this week",
        "this month", "this year", "recent", "recently", "newest", "price",
        "cost", "how much is", "release date", "released", "version",
        "who is the", "who won", "score", "stock", "weather", "news",
        "still ", "as of",
    )
    # Encyclopedic and slow-moving: safe to cache for longer.
    STABLE = (
        "plot", "who wrote", "who directed", "who invented", "born", "died",
        "history of", "what is", "what are", "definition", "meaning of",
        "how does", "why does", "explain",
    )
    # Signals the question is about the user, not the world. Matched on word
    # boundaries: naive substring matching makes "was i" fire inside "was
    # Interstellar", which silently classifies a world question as personal
    # and skips research entirely.
    PERSONAL_RE = re.compile(
        r"\b(?:i|me|my|mine|myself|we|us|our|ours)\b", re.IGNORECASE)
    LOOKUP_VERBS = ("who", "what", "when", "where", "which", "how many",
                    "how much", "how do", "how does", "is ", "are ", "did ", "does ")
    # Phrases that mark a checkable question about the world, even with no proper
    # noun or number and no volatile word — "what are the best guns in the finals"
    # is exactly this shape, and used to slip through and get answered from stale
    # recall or personal history instead of the web.
    FACTUAL_HINTS = ("best ", "top ", "tier list", "tierlist", " vs ", " versus ",
                     "compare", "cheapest", "fastest", "strongest", "review",
                     "recommend", "meta ", "how to ", "list of", "what is", "what are",
                     "who is", "who are", "where can", "where to")
    # Requests to be left to the model: creative, code, opinion, or "this"
    # operating on pasted content. These never go to the web.
    SKIP_RE = re.compile(
        r"\b(should i|do you think|your opinion|write|draft|compose|generate|"
        r"brainstorm|summari[sz]e this|summari[sz]e the|refactor|debug|rewrite|"
        r"translate this|explain this code|fix this|fix the)\b", re.IGNORECASE)

    def __init__(self, config: Config, now: Optional[Callable[[], datetime]] = None) -> None:
        self.config = config
        self._now = now or datetime.now
        self.cutoff_year = int(config.get("knowledge.model_cutoff_year", 2024))

    # -- classification ----------------------------------------------------
    def is_personal(self, question: str) -> bool:
        return bool(self.PERSONAL_RE.search(question))

    def category(self, question: str) -> str:
        text = question.lower()
        if any(word in text for word in self.VOLATILE):
            return "volatile"
        if any(word in text for word in self.STABLE):
            return "stable"
        return "default"

    def mentions_future_year(self, question: str) -> bool:
        """A year at or past the model's cutoff is a guaranteed knowledge gap."""
        for match in re.finditer(r"\b(19|20)\d{2}\b", question):
            if int(match.group(0)) >= self.cutoff_year:
                return True
        return False

    def needs_research(self, question: str) -> Optional[str]:
        """Return a search query when the web should be consulted, else None."""
        text = question.strip()
        if not text:
            return None
        if self.is_personal(text):
            # Their own history; the memory tools own this. The model can
            # still call research itself for a mixed question.
            return None

        if self.SKIP_RE.search(text):
            # Creative / code / opinion / "do this to my text" — the model owns these.
            return None
        lowered = text.lower()
        triggered = (
            self.mentions_future_year(text)
            or any(word in lowered for word in self.VOLATILE)
            or any(hint in lowered for hint in self.FACTUAL_HINTS)
            or any(lowered.startswith(v) for v in self.LOOKUP_VERBS)
        )
        if not triggered:
            return None
        return self._to_query(text)

    def _looks_factual(self, question: str) -> bool:
        """A checkable question about the world rather than a creative/code/opinion
        request. Deliberately generous: over-researching a factual question is
        cheap and cached, while under-researching makes it answer from stale
        recall — the failure the user actually hits."""
        return not self.SKIP_RE.search(question)

    @staticmethod
    def _to_query(question: str) -> str:
        query = question.strip().rstrip("?").strip()
        query = re.sub(r"^(please\s+)?(can you|could you|tell me|do you know)\s+", "",
                       query, flags=re.I)
        return query[:200]

    def ttl_for(self, question: str) -> float:
        category = self.category(question)
        key = {"volatile": "knowledge.volatile_ttl_sec",
               "stable": "knowledge.stable_ttl_sec"}.get(category, "knowledge.ttl_sec")
        return float(self.config.get(key, 86400))


@dataclass
class CachedAnswer:
    query: str
    answer: str
    sources: str
    fetched_at: float
    expires_at: float
    from_cache: bool

    def age_phrase(self) -> str:
        return human_age(self.fetched_at)


class KnowledgeCache:
    """Short-lived store of things looked up on the web.

    Kept separate from captured personal history: different lifetime,
    different sensitivity, and deleting one must never delete the other.
    """

    def __init__(self, config: Config, store: Store, web: WebTools,
                 gate: Optional[KnowledgeGate] = None,
                 researcher: Optional["DeepResearcher"] = None) -> None:
        self.config = config
        self.store = store
        self.web = web
        self.gate = gate or KnowledgeGate(config)
        self.researcher = researcher
        self.enabled = bool(config.get("knowledge.enabled", True))

    @staticmethod
    def make_key(query: str) -> str:
        normalized = re.sub(r"[^a-z0-9 ]+", " ", query.lower())
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return sha256_hex(normalized)

    def get(self, query: str) -> Optional[CachedAnswer]:
        if not self.enabled:
            return None
        row = self.store.knowledge_get(self.make_key(query))
        if row is None:
            return None
        return CachedAnswer(query=row["query"], answer=row["answer"], sources=row["sources"],
                            fetched_at=row["fetched_at"], expires_at=row["expires_at"],
                            from_cache=True)

    def put(self, query: str, answer: str, sources: str, category: str, ttl: float) -> None:
        if not self.enabled:
            return
        self.store.knowledge_put(self.make_key(query), query, answer, sources, category, ttl)

    def lookup(self, query: str, max_sources: int = 3, force_refresh: bool = False,
               on_round: Optional[Callable[[int, str], None]] = None) -> Optional[CachedAnswer]:
        """Cache-first research. Returns None only if the web is unusable.

        When a deep researcher is wired in and deep research is enabled, the
        fetch is a multi-round investigation rather than a single pass; the
        result is cached the same way regardless.
        """
        if not force_refresh:
            cached = self.get(query)
            if cached is not None:
                LOG.info("knowledge cache hit for %r (fetched %s)", query[:60],
                         cached.age_phrase())
                return cached
        if not self.web.enabled:
            return None
        try:
            if self.researcher is not None and self.config.get("knowledge.deep_research", True):
                digest = self.researcher.investigate(query, max_sources=max_sources,
                                                      on_round=on_round)
            else:
                digest = self.web.research(query, max_sources=max_sources)
        except MindError as exc:
            LOG.warning("research failed for %r: %s", query[:60], exc)
            return None
        if "could not read any" in digest or digest.startswith("No search results"):
            # Nothing worth caching; let the caller fall back.
            return CachedAnswer(query=query, answer=digest, sources="", fetched_at=now_ts(),
                                expires_at=now_ts(), from_cache=False)
        sources = "\n".join(re.findall(r"^\s{4}(https?://\S+)", digest, re.M))
        ttl = self.gate.ttl_for(query)
        category = self.gate.category(query)
        self.put(query, digest, sources, category, ttl)
        LOG.info("cached research for %r (%s, ttl %.0fh)", query[:60], category, ttl / 3600)
        return CachedAnswer(query=query, answer=digest, sources=sources, fetched_at=now_ts(),
                            expires_at=now_ts() + ttl, from_cache=False)


# ==========================================================================
# Consolidation: turning episodes into a durable profile of the user
# ==========================================================================
#
# The capture sources record what happened (episodes). This layer distils
# those into durable generalisations about the person — what they work on,
# the tools they use, projects, habits, stated preferences — and injects a
# compact version of that into every answer so the assistant walks in
# already knowing them, instead of only being able to look things up.
#
# Design commitments:
#   * Grounded: every fact cites the observations that produced it. Facts with
#     no evidence are dropped.
#   * Incremental: the current profile is shown to the model so it reports only
#     what is new, rather than re-deriving the same facts nightly.
#   * Semantic dedup: facts are embedded and merged by similarity, so a
#     rephrasing reinforces an existing fact instead of duplicating it.
#   * Decaying: a fact's weight fades unless it keeps being observed. Stale
#     generalisations sink and are pruned. Facts you add by hand never decay.
#   * Firewalled: health, politics, sexuality, finances, credentials and
#     armchair-psychology inferences are dropped before storage, always.
#   * Auditable: you can see every fact, why it is there, edit it, and delete
#     it line by line.


# Categories the reflector is allowed to use. Anything else is normalised to
# "general" so the taxonomy can't drift into sensitive territory.
PROFILE_CATEGORIES = (
    "work", "tools", "projects", "skills", "interests", "habits",
    "preferences", "context", "general",
)

# Hard firewall. If an inferred fact matches any of these, it is never stored.
# This mirrors the privacy stance of the capture redactor, applied to the
# model's *conclusions* rather than raw text — a small model will happily
# infer things about health or politics from thin evidence.
_SENSITIVE_PATTERNS = [
    ("health", re.compile(
        r"(?i)\b(depress|anxiet|anxious|adhd|autis|bipolar|diagnos|therapy|therapist|"
        r"medication|prescrib|disorder|disease|illness|symptom|mental health|addict|"
        r"recovery|sober|disab|chronic|insomnia|diabet|cancer)")),
    ("politics", re.compile(
        r"(?i)\b(democrat|republican|liberal|conservative|left-wing|right-wing|"
        r"vote[ds]?\b|political|politics|ideolog|libertarian|communist|socialist)")),
    ("religion", re.compile(
        r"(?i)\b(christian|muslim|hindu|jewish|buddhis|atheist|religio|faith|church|"
        r"mosque|temple|prays?\b|praying)")),
    ("sexuality", re.compile(
        r"(?i)\b(gay|lesbian|bisexual|straight|queer|sexual orientation|gender identity|"
        r"transgender|dating|romantic|relationship status|single|married|divorc)")),
    ("finance", re.compile(
        r"(?i)\b(salary|income|net worth|savings|debt|loan|mortgage|broke|wealthy|"
        r"poor|earns?\b|\$\d|credit score|bankrup)")),
    ("credentials", re.compile(
        r"(?i)\b(password|passphrase|api[_ -]?key|secret|token|private key|credential|"
        r"pin\b|ssn|social security)")),
    ("psych-profile", re.compile(
        r"(?i)\b(introvert|extrovert|narciss|neurotic|personality type|insecure|"
        r"lazy|anxious person|emotional|immature|arrogant)")),
    ("health-family", re.compile(r"(?i)\b(pregnan|miscarr|fertility)")),
]


def profile_sensitivity(text: str) -> Optional[str]:
    """Return the name of the firewall rule this fact trips, or None."""
    for name, pattern in _SENSITIVE_PATTERNS:
        if pattern.search(text):
            return name
    return None


def normalize_fact(text: str) -> str:
    """Lowercased, punctuation-stripped, stop-word-lite key for exact dedup."""
    lowered = re.sub(r"[^a-z0-9 ]+", " ", text.lower())
    tokens = [t for t in lowered.split() if t not in _FACT_STOPWORDS]
    return " ".join(tokens).strip()


_FACT_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "user", "users", "they", "them", "their", "he", "she", "his", "her",
    "to", "of", "in", "on", "for", "and", "or", "with", "that", "this",
    "who", "which", "has", "have", "had", "does", "do", "seems", "appears",
    "likely", "probably", "often", "regularly", "frequently",
}


@dataclass
class ProfileFact:
    id: int
    text: str
    category: str
    source: str
    confidence: float
    updated_at: float
    effective: float

    def confidence_bar(self, width: int = 5) -> str:
        filled = max(1, min(width, round(self.effective / 8.0 * width)))
        return "●" * filled + "○" * (width - filled)


class ProfileStore:
    """Persistence, decay ranking, and injection rendering for the profile."""

    def __init__(self, config: Config, store: Store) -> None:
        self.config = config
        self.store = store
        self.half_life_days = float(config.get("profile.half_life_days", 30.0))
        self.min_confidence = float(config.get("profile.min_confidence", 0.4))
        self.dedup_threshold = float(config.get("profile.dedup_threshold", 0.86))
        self.max_facts = int(config.get("profile.max_facts", 200))

    # -- decay -------------------------------------------------------------
    def effective_confidence(self, base: float, updated_at: float, source: str,
                             now: Optional[float] = None) -> float:
        """Confidence faded by how long since the fact was last observed.

        Manually-added facts do not decay: the user asserted them, so they
        stay until the user removes them.
        """
        if source == "manual":
            return max(base, 2.0)
        now = now if now is not None else now_ts()
        age_days = max(0.0, (now - updated_at) / 86400.0)
        if self.half_life_days <= 0:
            return base
        return base * (0.5 ** (age_days / self.half_life_days))

    def facts(self, now: Optional[float] = None) -> List[ProfileFact]:
        now = now if now is not None else now_ts()
        out: List[ProfileFact] = []
        for row in self.store.profile_list(limit=self.max_facts * 2):
            eff = self.effective_confidence(row["confidence"], row["updated_at"],
                                            row["source"], now)
            out.append(ProfileFact(id=row["id"], text=row["text"], category=row["category"],
                                   source=row["source"], confidence=row["confidence"],
                                   updated_at=row["updated_at"], effective=eff))
        out.sort(key=lambda f: f.effective, reverse=True)
        return out

    def prune(self, now: Optional[float] = None) -> int:
        """Drop facts that have decayed below the floor, and cap the total."""
        now = now if now is not None else now_ts()
        removed = 0
        surviving: List[ProfileFact] = []
        for fact in self.facts(now):
            if fact.source != "manual" and fact.effective < self.min_confidence:
                self.store.profile_delete(fact.id)
                removed += 1
            else:
                surviving.append(fact)
        # Cap: keep the strongest max_facts, evicting the weakest inferred ones.
        if len(surviving) > self.max_facts:
            for fact in surviving[self.max_facts:]:
                if fact.source != "manual":
                    self.store.profile_delete(fact.id)
                    removed += 1
        return removed

    # -- dedup -------------------------------------------------------------
    def find_similar(self, vector: Optional[Sequence[float]], norm: str
                     ) -> Optional[int]:
        """Return the id of an existing fact this one restates, or None."""
        exact = self.store.profile_by_norm(norm)
        if exact is not None:
            return int(exact["id"])
        if not vector:
            return None
        best_id, best_score = None, 0.0
        query = normalize_vector(vector)
        for row in self.store.profile_vectors():
            blob = row["embedding"]
            if not blob or row["dim"] != len(query):
                continue
            other = unpack_vector(blob)
            score = sum(a * b for a, b in zip(query, other))
            if score > best_score:
                best_id, best_score = int(row["id"]), score
        if best_id is not None and best_score >= self.dedup_threshold:
            return best_id
        return None

    # -- injection ---------------------------------------------------------
    def render(self, budget_chars: int = 900) -> str:
        """A compact, ranked profile block for the model's context."""
        facts = [f for f in self.facts() if f.effective >= self.min_confidence]
        if not facts:
            return ""
        by_cat: Dict[str, List[str]] = {}
        used = 0
        for fact in facts:
            line = fact.text.strip().rstrip(".")
            if used + len(line) > budget_chars:
                break
            by_cat.setdefault(fact.category, []).append(line)
            used += len(line) + 2
        if not by_cat:
            return ""
        parts = []
        for category in PROFILE_CATEGORIES:
            if category in by_cat:
                parts.append(f"{category}: " + "; ".join(by_cat[category]))
        for category, items in by_cat.items():
            if category not in PROFILE_CATEGORIES:
                parts.append("; ".join(items))
        return "\n".join(parts)


REFLECTION_PROMPT = """You maintain a durable profile of a person from observations of their \
own computer activity (apps they focus on, things they copy, pages they visit, files they edit).

Extract DURABLE, GENERAL facts about this person — the kind that stay true for weeks or months:
what they work on, the tools and languages they use, ongoing projects, skills, genuine interests, \
working habits, and clearly-stated preferences.

Do NOT output:
- one-off events ("opened Chrome", "watched a video") — only lasting generalisations
- anything about health, mental health, politics, religion, sexuality, relationships, finances, \
or personal identity
- guesses about personality or character
- facts about OTHER people — only this person
- anything you cannot support from the observations below

{known_block}

OBSERVATIONS (numbered):
{observations}

Return ONLY a JSON array. Each element:
  {{"fact": "<short durable statement>", "category": "<one of: work, tools, projects, skills, \
interests, habits, preferences, context>", "evidence": [<observation numbers that support it>]}}

Rules: 3-10 words per fact. Every fact needs at least one evidence number. Prefer to say nothing \
over guessing. If nothing durable and new stands out, return []."""


class Reflector:
    """Runs the consolidation pass: observations -> durable profile facts."""

    def __init__(self, config: Config, store: Store, client: OllamaClient,
                 profile: Optional[ProfileStore] = None) -> None:
        self.config = config
        self.store = store
        self.client = client
        self.profile = profile or ProfileStore(config, store)
        self.chat_model = config.get("chat_model")
        self.embed_model = config.get("embed_model")
        self.max_observations = int(config.get("profile.max_observations", 200))

    # -- observation gathering --------------------------------------------
    def _checkpoint(self) -> float:
        return float(self.store.get_meta("profile_reflected_at", "0") or 0)

    def _set_checkpoint(self, ts: float) -> None:
        self.store.set_meta("profile_reflected_at", str(ts))

    def _gather(self) -> Tuple[List[sqlite3.Row], float]:
        since = self._checkpoint()
        rows = self.store.captures_since(since, limit=self.max_observations)
        # Return oldest-first so evidence numbers read chronologically.
        rows = list(reversed(rows))
        newest = max((r["ts"] for r in rows), default=now_ts())
        return rows, newest

    @staticmethod
    def _format_observations(rows: Sequence[sqlite3.Row]) -> str:
        lines = []
        for index, row in enumerate(rows, start=1):
            text = normalize_ws(row["text"])[:160]
            where = f" [{row['origin']}]" if row["origin"] else ""
            lines.append(f"{index}. ({row['source']}{where}) {text}")
        return "\n".join(lines)

    def _known_block(self) -> str:
        facts = self.profile.facts()[:40]
        if not facts:
            return "The profile is currently empty."
        listed = "; ".join(f.text.strip().rstrip(".") for f in facts)
        return ("ALREADY KNOWN (do not repeat these; only report what is new or clearly "
                f"different):\n{listed}")

    # -- model output parsing ---------------------------------------------
    @staticmethod
    def _parse(text: str) -> List[dict]:
        """Tolerantly extract the JSON array a small model was asked for."""
        if not text:
            return []
        fenced = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.S)
        candidate = fenced.group(1) if fenced else None
        if candidate is None:
            start = text.find("[")
            end = text.rfind("]")
            if start == -1 or end <= start:
                return []
            candidate = text[start:end + 1]
        candidate = re.sub(r",\s*([\]}])", r"\1", candidate)  # trailing commas
        try:
            data = json.loads(candidate)
        except ValueError:
            return []
        if not isinstance(data, list):
            return []
        out = []
        for item in data:
            if isinstance(item, dict) and item.get("fact"):
                out.append(item)
        return out

    # -- the pass ----------------------------------------------------------
    def reflect(self, force: bool = False) -> Dict[str, Any]:
        """Run one consolidation pass. Returns a summary; never raises."""
        summary = {"observations": 0, "added": 0, "reinforced": 0,
                   "skipped_sensitive": 0, "skipped_empty": 0, "error": None}
        try:
            rows, newest = self._gather()
            summary["observations"] = len(rows)
            if len(rows) < int(self.config.get("profile.min_observations", 5)) and not force:
                return summary
            if not rows:
                return summary

            prompt = REFLECTION_PROMPT.format(
                known_block=self._known_block(),
                observations=self._format_observations(rows))
            messages = [{"role": "user", "content": prompt}]
            options = {"temperature": 0.2,
                       "num_ctx": int(self.config.get("runtime.num_ctx", 8192))}
            raw = self.client.chat(self.chat_model, messages, options)
            candidates = self._parse(raw)

            id_by_index = {i: rows[i - 1]["id"] for i in range(1, len(rows) + 1)}
            ts_by_index = {i: rows[i - 1]["ts"] for i in range(1, len(rows) + 1)}

            for item in candidates:
                fact = normalize_ws(str(item.get("fact", "")))[:160]
                if not fact or len(fact.split()) < 2:
                    summary["skipped_empty"] += 1
                    continue
                reason = profile_sensitivity(fact)
                if reason is not None:
                    summary["skipped_sensitive"] += 1
                    LOG.info("reflection dropped a %s inference", reason)
                    continue
                evidence_ids = []
                evidence_ts = []
                for ref in item.get("evidence", []) or []:
                    with contextlib.suppress(ValueError, TypeError):
                        ref_i = int(ref)
                        if ref_i in id_by_index:
                            evidence_ids.append(id_by_index[ref_i])
                            evidence_ts.append(ts_by_index[ref_i])
                if not evidence_ids:
                    summary["skipped_empty"] += 1
                    continue

                category = str(item.get("category", "general")).lower().strip()
                if category not in PROFILE_CATEGORIES:
                    category = "general"
                evidence = {"from": min(evidence_ts), "to": max(evidence_ts),
                            "obs": evidence_ids[:8], "n": len(evidence_ids)}

                vector = None
                with contextlib.suppress(OllamaError):
                    vector = self.client.embed_one(fact, self.embed_model)

                norm = normalize_fact(fact)
                existing = self.profile.find_similar(vector, norm)
                if existing is not None:
                    self.store.profile_reinforce(existing, evidence, category)
                    summary["reinforced"] += 1
                else:
                    self.store.profile_insert(fact, norm, category, evidence,
                                              source="inferred", confidence=1.0, vector=vector)
                    summary["added"] += 1

            self.profile.prune()
            self._set_checkpoint(newest)
            return summary
        except (OllamaError, StorageError) + DB_ERRORS as exc:
            summary["error"] = str(exc)
            LOG.warning("reflection pass failed: %s", exc)
            return summary

    # -- manual entry ------------------------------------------------------
    def add_manual(self, fact: str, category: str = "general") -> bool:
        fact = normalize_ws(fact)[:160]
        if not fact:
            return False
        if profile_sensitivity(fact) is not None:
            raise MindError("that looks like a sensitive category the profile won't store")
        if category not in PROFILE_CATEGORIES:
            category = "general"
        vector = None
        with contextlib.suppress(OllamaError):
            vector = self.client.embed_one(fact, self.embed_model)
        norm = normalize_fact(fact)
        existing = self.profile.find_similar(vector, norm)
        if existing is not None:
            self.store.profile_reinforce(existing, {"manual": True}, category, bump=2.0)
            return False
        self.store.profile_insert(fact, norm, category, {"manual": True},
                                  source="manual", confidence=3.0, vector=vector)
        return True


# ==========================================================================
# CLI helpers
# ==========================================================================

def resolve_paths(args: argparse.Namespace) -> Paths:
    home = Path(args.home).expanduser() if getattr(args, "home", None) else default_home()
    paths = Paths(home)
    paths.ensure()
    return paths


def load_config_or_die(paths: Paths, require_setup: bool = True) -> Config:
    config = Config.load(paths)
    problems = config.validate()
    if problems:
        raise ConfigError("config problems:\n  - " + "\n  - ".join(problems))
    if require_setup and not config.get("chat_model"):
        raise ConfigError(f"no chat model configured yet — run `{APP_NAME} setup` first")
    return config


def make_client(config: Config) -> OllamaClient:
    return OllamaClient(
        config.get("ollama_url"),
        timeout=float(config.get("runtime.http_timeout_sec", 120)),
        chat_timeout=float(config.get("runtime.chat_timeout_sec", 600)),
    )


def prompt(question: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{question}{suffix}: ").strip()
    except EOFError:
        return default
    return answer or default


def prompt_bool(question: str, default: bool = False) -> bool:
    answer = prompt(f"{question} (y/n)", "y" if default else "n").lower()
    return answer.startswith("y")


_YES_NO_WORDS = {"y", "n", "yes", "no", "true", "false"}

# Config keys whose value must be a list, so a bare string can be coerced
# instead of rejected. PowerShell strips inner double quotes from arguments to
# native commands, so a perfectly reasonable `--set key=["a","b"]` arrives here
# as the string `[a,b]`; refusing that teaches shell escaping instead of
# solving the problem.
_LIST_KEYS = {
    "sources.files.folders",
    "sources.files.extensions",
    "sources.files.exclude_dirs",
    "privacy.app_denylist",
    "privacy.title_denylist",
}


def coerce_config_value(key: str, value: Any, existing: Any = None) -> Any:
    """Turn shell-mangled scalars into the shape the key actually needs."""
    wants_list = key in _LIST_KEYS or isinstance(existing, list)
    if not wants_list or isinstance(value, list) or not isinstance(value, str):
        return value
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    parts = [part.strip().strip('"').strip("'") for part in text.split(",")]
    return [part for part in parts if part]


def _prompt_folders(current: Sequence[str], c: Console, attempts: int = 3) -> List[str]:
    """Ask for watch folders, rejecting the answers people give by reflex.

    This prompt follows two yes/no questions, so 'y' is a very easy thing to
    type here — and a folder called 'y' fails silently forever afterwards.
    """
    default = ", ".join(current)
    for attempt in range(attempts):
        raw = prompt("Folders to index (full paths, comma-separated)", default)
        candidates = [part.strip() for part in raw.split(",") if part.strip()]
        if not candidates:
            return []
        if any(word.lower() in _YES_NO_WORDS for word in candidates):
            c.warn("that looks like a yes/no answer — this prompt wants a real path, "
                   "e.g. " + (r"C:\Users\you\Notes" if IS_WINDOWS else "~/Notes"))
            default = ""
            continue
        folders, missing = [], []
        for part in candidates:
            path = Path(part).expanduser()
            if path.exists() and path.is_dir():
                folders.append(str(path))
            else:
                missing.append(str(path))
        if missing:
            c.warn("not found: " + ", ".join(missing))
            if not folders and attempt + 1 < attempts:
                default = ""
                continue
        if folders:
            for folder in folders:
                c.ok(f"will index {folder}")
            return folders
    return []


def heartbeat_state(paths: Paths) -> Tuple[str, Optional[dict]]:
    """Return ('running'|'stale'|'paused'|'never', payload)."""
    if not paths.heartbeat.exists():
        return "never", None
    try:
        with open(paths.heartbeat, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return "stale", None
    age = now_ts() - float(payload.get("ts", 0))
    if age > 60:
        return "stale", payload
    # The pause flag is a file, so read it directly rather than waiting for the
    # daemon's next heartbeat to reflect it.
    if paths.paused.exists() or payload.get("paused"):
        return "paused", payload
    if not payload.get("running", True):
        return "stale", payload
    return "running", payload


# ==========================================================================
# Command: setup
# ==========================================================================

def cmd_setup(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = Config.load(paths)
    c = CONSOLE

    c.header(f"{APP_NAME} {VERSION} — setup")
    c.write(c.dim("Everything stays on this machine. Press Enter to accept defaults.\n"))

    url = prompt("Ollama URL", config.get("ollama_url"))
    config.set("ollama_url", url)
    client = OllamaClient(url)

    models: List[ModelInfo] = []
    if client.is_up():
        with contextlib.suppress(OllamaError):
            models = client.list_models()
        if models:
            c.write("\nModels on this server:")
            for model in models:
                size = f" ({human_bytes(model.size)})" if model.size else ""
                c.write(f"  - {model.name}{size}")
        else:
            c.write(c.yellow("\nOllama is running but has no models pulled yet."))
    else:
        c.write(c.yellow(f"\nCan't reach Ollama at {url} — start it, then re-run setup "
                         f"(you can still finish configuring now)."))

    names = [m.name for m in models]
    chat_default = config.get("chat_model") or next(
        (n for n in names if not any(tag in n for tag in ("embed", "bge", "minilm"))), "")
    chat_model = prompt("\nChat model", chat_default)
    if not chat_model:
        c.write(c.red("A chat model is required. Try: ollama pull qwen2.5:7b"))
        return 2
    config.set("chat_model", chat_model)

    embed_default = config.get("embed_model") or "nomic-embed-text"
    embed_model = prompt("Embedding model", embed_default)
    config.set("embed_model", embed_model)

    if client.is_up():
        for model in (chat_model, embed_model):
            if not client.has_model(model):
                if prompt_bool(f"{model} isn't pulled yet. Pull it now?", True):
                    c.write(f"Pulling {model} …")
                    try:
                        last = ""
                        for line in client.pull(model):
                            if line != last:
                                c.raw(f"\r  {line[:70]:<70}")
                                last = line
                        c.write("")
                        c.ok(f"pulled {model}")
                    except OllamaError as exc:
                        c.write("")
                        c.fail(f"pull failed: {exc}")

    days = prompt("\nRetention window in days (how far back it can remember)",
                  str(config.get("retention_days")))
    with contextlib.suppress(ValueError):
        config.set("retention_days", max(1, int(days)))

    c.header("Sources — everything is off unless you turn it on")
    adapter = make_adapter()

    clip_on = prompt_bool("Capture clipboard?", bool(config.get("sources.clipboard.enabled")))
    config.set("sources.clipboard.enabled", clip_on)
    if clip_on and adapter.get_clipboard() is None:
        c.warn("clipboard looks unreadable right now — it may just be empty, "
               "or the platform tool is missing (see `doctor`)")

    focus_on = prompt_bool("Capture app/window focus history?",
                           bool(config.get("sources.focus.enabled")))
    config.set("sources.focus.enabled", focus_on)
    if focus_on and adapter.get_focus() is None:
        c.warn("window focus is unreadable right now (on macOS grant Accessibility; "
               "on Linux install xdotool)")

    browser_on = prompt_bool("Capture browser history (gives real URLs, not just titles)?",
                             bool(config.get("sources.browser.enabled")))
    config.set("sources.browser.enabled", browser_on)
    if browser_on:
        profiles = len(firefox_profile_dirs())
        chromium = len(chromium_history_files())
        if profiles or chromium:
            c.ok(f"found {profiles} Firefox profile(s) and {chromium} Chromium profile(s)")
        else:
            c.warn("no browser history databases found — check that the browser is installed "
                   "for this user account")

    files_on = prompt_bool("Index text files in folders?",
                           bool(config.get("sources.files.enabled")))
    config.set("sources.files.enabled", files_on)
    if files_on:
        folders = _prompt_folders(config.get("sources.files.folders", []), c)
        config.set("sources.files.folders", folders)
        if not folders:
            config.set("sources.files.enabled", False)
            c.warn("no valid folders given — file indexing left off. Turn it on later with "
                   f"`{APP_NAME} config --set sources.files.folders='[\"/path/to/notes\"]'`")

    config.save(paths)
    c.write("")
    c.ok(f"saved {paths.config}")

    if client.is_up() and client.has_model(embed_model):
        try:
            vector = client.embed_one("connection test", embed_model)
            c.ok(f"embedding model works ({len(vector)} dimensions)")
        except OllamaError as exc:
            c.fail(f"embedding test failed: {exc}")

    c.header("Next")
    c.write(f"  {APP_NAME} doctor      # verify everything")
    c.write(f"  {APP_NAME} install     # start capturing automatically at login")
    c.write(f"  {APP_NAME} chat        # talk to it")
    return 0


# ==========================================================================
# Command: doctor
# ==========================================================================

def cmd_doctor(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    c = CONSOLE
    failures = 0
    warnings = 0

    c.title(f"{APP_NAME} {VERSION}", "doctor")

    c.section("Environment")
    if sys.version_info >= (3, 8):
        c.ok(f"python {platform.python_version()} ({platform.system()} {platform.machine()})")
    else:
        c.fail(f"python {platform.python_version()} is too old; need 3.8+")
        failures += 1

    if HAVE_NUMPY:
        c.ok(f"numpy {_np.__version__} — fast vector search enabled")
    else:
        c.warn("numpy not installed — using the quantized fallback. "
               "`pip install numpy` makes search much faster on large databases")
        warnings += 1

    probe = Store(paths.db)
    if probe.has_fts:
        c.ok(f"sqlite {sqlite3.sqlite_version} with FTS5 (keyword search enabled)")
    else:
        c.warn(f"sqlite {sqlite3.sqlite_version} without FTS5 — keyword search falls back to LIKE")
        warnings += 1

    try:
        usage = shutil.disk_usage(paths.home)
        if usage.free < 500_000_000:
            c.warn(f"only {human_bytes(usage.free)} free on the data volume")
            warnings += 1
        else:
            c.ok(f"{human_bytes(usage.free)} free disk")
    except OSError:
        pass

    c.section("Configuration")
    try:
        config = Config.load(paths)
        problems = config.validate()
        if problems:
            for problem in problems:
                c.fail(problem)
            failures += len(problems)
        else:
            c.ok(f"config valid ({paths.config})")
        if not config.get("chat_model"):
            c.fail(f"no chat model set — run `{APP_NAME} setup`")
            failures += 1
        sources = config.enabled_sources()
        if sources:
            c.ok(f"sources enabled: {', '.join(sources)}")
        else:
            c.warn("no sources enabled — nothing will be captured")
            warnings += 1
    except ConfigError as exc:
        c.fail(str(exc))
        probe.close()
        return 1

    c.section("Ollama")
    client = make_client(config)
    if not client.is_up():
        c.fail(f"cannot reach {config.get('ollama_url')} — start Ollama and retry")
        failures += 1
    else:
        c.ok(f"reachable at {config.get('ollama_url')}")
        try:
            available = [m.name for m in client.list_models()]
            c.ok(f"{len(available)} model(s) installed")
        except OllamaError as exc:
            c.fail(f"model list failed: {exc}")
            failures += 1
            available = []

        for label, model in (("chat", config.get("chat_model")),
                             ("embedding", config.get("embed_model"))):
            if not model:
                continue
            if client.has_model(model):
                c.ok(f"{label} model present: {model}")
            else:
                c.fail(f"{label} model missing: {model} → run `ollama pull {model}`")
                failures += 1

        if client.has_model(config.get("embed_model")):
            try:
                started = time.time()
                vector = client.embed_one("doctor probe", config.get("embed_model"))
                elapsed = (time.time() - started) * 1000
                c.ok(f"embeddings working ({len(vector)} dims, {elapsed:.0f} ms)")
                stored_dim = probe.dominant_dim()
                if stored_dim and stored_dim != len(vector):
                    c.warn(f"stored vectors are {stored_dim}-dim but the model returns "
                           f"{len(vector)} — run `{APP_NAME} reindex` after changing embed models")
                    warnings += 1
            except OllamaError as exc:
                c.fail(f"embedding call failed: {exc}")
                failures += 1

    c.section("Capture")
    adapter = make_adapter()
    c.ok(f"platform adapter: {adapter.name}")
    if config.get("sources.clipboard.enabled"):
        if adapter.get_clipboard() is not None:
            c.ok("clipboard readable")
        else:
            c.warn("clipboard not readable right now (may just be empty)")
            warnings += 1
    if config.get("sources.focus.enabled"):
        focus = adapter.get_focus()
        if focus:
            c.ok(f"window focus readable (now: {focus.app})")
        else:
            hint = ("grant Automation access to this terminal" if IS_MACOS else
                    "install xdotool" if IS_LINUX else "no window is focused")
            c.fail(f"window focus unreadable — {hint}")
            failures += 1
        if IS_MACOS and hasattr(adapter, "probe_focus_permission"):
            status, detail = adapter.probe_focus_permission()
            if status == "ok":
                c.ok(f"window titles readable (Accessibility granted) — {detail[:48]}")
            elif status == "denied":
                c.fail(f"window titles blocked: {detail}. System Settings > Privacy & "
                       f"Security > Accessibility, add the app running this script")
                failures += 1
            elif status == "no-window":
                c.warn(f"couldn't confirm window titles right now ({detail}); "
                       f"focus a normal app window and re-run")
                warnings += 1
            else:
                c.warn(f"focus probe inconclusive: {detail}")
                warnings += 1

    if config.get("sources.files.enabled"):
        protected = {"desktop", "documents", "downloads"}
        for folder in config.get("sources.files.folders", []):
            path = Path(folder).expanduser()
            if not path.exists():
                c.fail(f"watch folder missing: {folder}")
                failures += 1
                continue
            try:
                next(iter(os.scandir(path)), None)
                c.ok(f"watch folder readable: {folder}")
            except PermissionError:
                c.fail(f"watch folder not readable (grant Full Disk Access): {folder}")
                failures += 1
                continue
            if IS_MACOS:
                relative = {part.lower() for part in path.parts}
                if relative & protected:
                    c.warn(f"{folder} is TCC-protected — the launchd agent needs Full Disk "
                           f"Access for {sys.executable}, even though your terminal can read it")
                    warnings += 1

    if IS_MACOS:
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_LABEL}.plist"
        if plist_path.exists():
            try:
                text = plist_path.read_text(encoding="utf-8")
            except OSError:
                text = ""
            if sys.executable and sys.executable not in text:
                c.warn("the installed launch agent runs a different Python than this one — "
                       f"its permissions won't match. Re-run `{APP_NAME} install` to update it")
                warnings += 1
            else:
                c.ok("launch agent matches this Python interpreter")

    if config.get("sources.browser.enabled"):
        # Enumerate every browser DB and actually try to open it read-only, so
        # a macOS Full Disk Access block surfaces here instead of failing
        # silently at capture time (the #1 "nothing gets captured" cause).
        wanted = {b.lower() for b in config.get("sources.browser.browsers", [])}
        dbs: List[Tuple[str, Path]] = []
        if "firefox" in wanted:
            dbs += [(f"firefox:{i}", p / "places.sqlite")
                    for i, p in enumerate(firefox_profile_dirs())]
        dbs += [(name, path) for name, path in chromium_history_files()
                if name.split(":")[0] in wanted]
        if "safari" in wanted:
            safari = safari_history_file()
            if safari is not None:
                dbs.append(("safari", safari))

        if not dbs:
            c.warn("browser capture is on, but no browser history database was found "
                   "for the enabled browsers — is the browser installed for this user?")
            warnings += 1
        else:
            readable, blocked = [], []
            for name, path in dbs:
                try:
                    conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=3)
                    conn.execute("SELECT 1")
                    conn.close()
                    readable.append(name)
                except DB_ERRORS:
                    blocked.append(name)
            if readable:
                c.ok(f"browser history readable: {', '.join(readable)}")
            for name in blocked:
                if IS_MACOS:
                    c.fail(f"{name} history exists but can't be read — grant Full Disk Access "
                           f"to {sys.executable} in System Settings > Privacy & Security")
                else:
                    c.fail(f"{name} history exists but can't be opened (locked or permission)")
                failures += 1

    c.section("Network")
    if config.get("network.enabled"):
        c.ok("network access is ON — the assistant may fetch pages you or your history supply")
        denied = config.get("network.domain_denylist", [])
        c.write(f"       denylist: {', '.join(denied) if denied else '(empty)'}")
    else:
        c.ok("network access is OFF (memory tools only)")
    if config.get("chat_model"):
        client_probe = make_client(config)
        if client_probe.is_up():
            if client_probe.supports_tools(config.get("chat_model")):
                c.ok(f"{config.get('chat_model')} supports tool calling — `{APP_NAME} agent` works")
            else:
                c.warn(f"{config.get('chat_model')} does not support tool calling; "
                       f"`{APP_NAME} agent` needs qwen2.5, llama3.1/3.2 or similar")
                warnings += 1

    state, payload = heartbeat_state(paths)
    if state == "running":
        c.ok(f"capture daemon running (pid {payload.get('pid')})")
    elif state == "paused":
        c.warn("capture daemon running but PAUSED (`resume` to continue)")
        warnings += 1
    elif state == "stale":
        c.warn(f"capture daemon not running — start it with `{APP_NAME} install` "
               f"or `{APP_NAME} capture`")
        warnings += 1
    else:
        c.warn("capture has never run")
        warnings += 1

    c.section("Database")
    if probe.integrity_ok():
        c.ok("integrity check passed")
    else:
        c.fail("integrity check FAILED — consider `forget --all` to rebuild")
        failures += 1
    stats = probe.stats()
    c.ok(f"{stats['total']} entries, {human_bytes(stats['db_bytes'])} on disk")
    if stats["pending"]:
        c.warn(f"{stats['pending']} entries still waiting for embeddings "
               f"(they backfill automatically while capture runs)")
        warnings += 1
    dims = probe.dim_histogram()
    if len(dims) > 1:
        c.warn(f"mixed embedding dimensions {dims} — run `{APP_NAME} reindex`")
        warnings += 1
    probe.close()

    c.section("Encryption at rest")
    if is_encrypted(paths.home):
        c.ok(f"database is encrypted ({encryption_state(paths.home).get('provider')} key)")
    else:
        c.warn("database is NOT encrypted — captured text sits on disk in the clear")
        c.sub(f"turn it on: {APP_NAME} encrypt on")
        warnings += 1
    # Disk encryption is about the machine, not a broken install, so it warns
    # rather than failing — doctor's exit code means "this setup is broken".
    fde_on, fde_text = disk_encryption_status()
    if fde_on is True:
        c.ok(f"full-disk encryption: {fde_text}")
    elif fde_on is False:
        c.warn(f"full-disk encryption: {fde_text}")
        c.sub("this is the defence that matters most for a lost or stolen "
              "machine — turn on BitLocker/FileVault")
        warnings += 1
    else:
        c.warn(f"full-disk encryption: {fde_text}")
        warnings += 1

    c.write("")
    c.rule()
    def plural(n: int, word: str) -> str:
        return f"{n} {word}{'s' if n != 1 else ''}"

    if failures:
        c.write(f"  {c.red(c.g('fail'))}  {c.bold(plural(failures, 'problem'))}"
                f"   {c.dim(plural(warnings, 'warning'))}")
        c.write("")
        return 1
    tail = f"   {c.dim(plural(warnings, 'warning'))}" if warnings else ""
    c.write(f"  {c.green(c.g('ok'))}  {c.bold('All good.')}{tail}")
    c.write("")
    return 0


# ==========================================================================
# Command: capture
# ==========================================================================

def cmd_capture(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = load_config_or_die(paths)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=not args.quiet)
    daemon = Daemon(config, paths)
    return daemon.run()


# ==========================================================================
# Command: chat / ask
# ==========================================================================

SYSTEM_PROMPT = """You are {app}, a personal assistant running entirely on the user's own machine.
The current local time is {now} ({weekday}).

You may be given a CONTEXT block: numbered snippets captured from the user's own activity
(clipboard, app/window focus history, and files they chose to index). Rules for using it:
- Use context snippets when they are relevant, and cite them inline like [1] or [2].
- Snippets are raw captures, not verified facts. Window titles show what was open, not what was done.
- If the context does not answer the question, say so plainly, then answer from general knowledge
  and make clear which part came from where.
- Never invent captures, timestamps, or sources that are not in the context.
- Each snippet header gives its weekday, date, time and how long ago it was. Use those
  for any question about when something happened, and quote the actual times back.
- If the context holds nothing from the time period the user asked about, say exactly
  that ("I have nothing captured from Tuesday") instead of answering with whatever else
  was retrieved. A wrong-day answer is worse than admitting the gap.
Be concise and direct."""


def _render_sources(console: Console, hits: Sequence[Hit]) -> None:
    if not hits:
        return
    console.write("")
    console.write(f"  {console.dim('sources:')}")
    for index, hit in enumerate(hits, start=1):
        snippet = " ".join(hit.text.split())[:70]
        console.write(f"   {console.cyan(f'[{index}]')} {console.dim(hit.label())}"
                      f"  {console.dim(snippet)}")


def chat_options(config: Config) -> dict:
    """Options sent with every chat call.

    num_ctx matters more than anything else here: Ollama defaults to a small
    window and silently truncates from the FRONT of an oversized prompt, which
    eats the system prompt and the earliest retrieved snippets. Leaving it
    unset makes a capable model look incoherent.
    """
    return {"num_ctx": int(config.get("runtime.num_ctx", 8192))}


def estimate_tokens(messages: Sequence[dict]) -> int:
    """Rough prompt size (~4 chars per token) — enough to catch overflow."""
    return sum(len(m.get("content", "")) for m in messages) // 4


def _answer(client: OllamaClient, model: str, messages: List[dict], console: Console,
            stream: bool = True, options: Optional[dict] = None) -> str:
    pieces: List[str] = []
    if stream:
        for piece in client.chat_stream(model, messages, options):
            pieces.append(piece)
            console.raw(piece)
        console.write("")
    else:
        text = client.chat(model, messages, options)
        pieces.append(text)
        console.write(text)
    return "".join(pieces)


def _prepare_messages(retriever: Optional[Retriever], query: str, history: List[dict],
                      days: Optional[int]) -> Tuple[List[dict], List[Hit]]:
    now = datetime.now()
    system = SYSTEM_PROMPT.format(
        app=APP_NAME,
        now=now.strftime("%Y-%m-%d %H:%M").strip(),
        weekday=now.strftime("%A"))
    messages: List[dict] = [{"role": "system", "content": system}]
    hits: List[Hit] = []
    if retriever is not None:
        hits = retriever.retrieve(query, days=days)
        context, hits = retriever.build_context(hits)
        if context:
            messages.append({"role": "system", "content": f"CONTEXT:\n{context}"})
    messages.extend(history[-10:])
    messages.append({"role": "user", "content": query})
    return messages, hits


def cmd_chat(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = load_config_or_die(paths)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=False)
    c = CONSOLE

    client = make_client(config)
    if not client.is_up():
        raise MindError(f"Ollama is not reachable at {config.get('ollama_url')}. Start it and retry.")
    model = args.model or config.get("chat_model")
    if not client.has_model(model):
        raise MindError(f"model {model!r} is not installed. Run: ollama pull {model}")

    store = Store(paths.db)
    index = VectorIndex(max_vectors=int(config.get("runtime.max_vectors", 150_000)))
    peers_ok = not getattr(args, "local", False)
    retriever = (None if args.no_memory
                 else make_retriever(config, store, index, client, allow_peers=peers_ok))

    # One brain, not two. If the model can call tools, chat runs the full
    # agent every turn: the gate researches world questions before answering,
    # timeline handles time questions, and the knowledge cache avoids
    # re-fetching. Only fall back to plain retrieval when tools are impossible.
    web = WebTools(config)
    researcher = DeepResearcher(config, web, client, model)
    knowledge = KnowledgeCache(config, store, web, researcher=researcher)
    tools = ToolBox(config, store, retriever, web, knowledge, researcher=researcher)
    profile = ProfileStore(config, store)
    agent_mode = (not args.no_agent and not args.no_memory
                  and bool(config.get("agent.enabled", True))
                  and client.supports_tools(model))

    days = args.days if args.days is not None else int(config.get("retention_days", 30))
    session_id = store.latest_session() if args.resume else None
    if session_id is None:
        session_id = store.create_session()
    history = store.session_messages(session_id) if args.resume else []

    options = chat_options(config)
    stats = store.stats()
    mode_label = "agent" if agent_mode else "retrieval-only"
    net_label = "web on" if config.get("network.enabled") else "web off"
    sep = f"  {c.g('bullet')}  "
    c.write("")
    c.write(f"  {c.bold(APP_NAME)} {c.dim(VERSION)}")
    c.write("  " + c.dim(sep.join([model, mode_label, net_label,
                                   f"{stats['total']:,} memories"])))
    c.rule()
    if agent_mode and not config.get("network.enabled"):
        c.write(c.dim(f"  tip: turn on the web with `{APP_NAME} config --set network.enabled=true`"))
    elif not agent_mode and not args.no_agent and not args.no_memory:
        c.write(c.yellow(f"  {model} can't call tools — running retrieval only. "
                         f"For auto-research use a model like qwen2.5 or llama3.1."))
    c.write(c.dim("/help for commands, Ctrl+C to interrupt, /quit to exit\n"))

    while True:
        try:
            prompt_text = (f"{c.cyan(c.g('chev'))} " if c.color
                           else f"{c.g('chev')} ")
            query = input(prompt_text).strip()
        except (EOFError, KeyboardInterrupt):
            c.write("")
            break
        if not query:
            continue

        if query.startswith("/"):
            command, _, argument = query[1:].partition(" ")
            command = command.lower()
            if command in ("quit", "exit", "q"):
                break
            if command == "help":
                c.write("")
                for name, description in (
                        ("/days N", "change the memory window"),
                        ("/model NAME", "switch chat model"),
                        ("/agent on|off", "toggle auto-research + tools"),
                        ("/trace on|off", "show the tool calls each answer makes"),
                        ("/sources", "show what the last answer used"),
                        ("/context", "print the exact prompt the model received"),
                        ("/stats", "database statistics"),
                        ("/reset", "start a fresh conversation"),
                        ("/memory on|off", "toggle retrieval"),
                        ("/quit", "exit")):
                    c.write(f"  {c.cyan(name.ljust(15))} {c.dim(description)}")
                c.write("")
                continue
            if command == "agent":
                want = argument.strip().lower() != "off"
                if want and not client.supports_tools(model):
                    c.write(c.yellow(f"  {model} can't call tools; staying in retrieval mode"))
                else:
                    agent_mode = want
                    c.write(c.dim(f"  agent mode {'on' if agent_mode else 'off'}"))
                continue
            if command == "trace":
                cmd_chat._trace = argument.strip().lower() != "off"  # type: ignore[attr-defined]
                c.write(c.dim(f"  trace {'on' if cmd_chat._trace else 'off'}"))
                continue
            if command == "days" and argument.strip().isdigit():
                days = int(argument.strip())
                c.write(c.dim(f"  memory window: {days}d"))
                continue
            if command == "model" and argument.strip():
                candidate = argument.strip()
                if client.has_model(candidate):
                    model = candidate
                    c.write(c.dim(f"  model: {model}"))
                else:
                    c.write(c.yellow(f"  {candidate} is not installed"))
                continue
            if command == "sources":
                _render_sources(c, getattr(cmd_chat, "_last_hits", []))
                continue
            if command == "context":
                sent = getattr(cmd_chat, "_last_messages", [])
                if not sent:
                    c.write(c.dim("  ask something first"))
                    continue
                for message in sent:
                    c.write(c.dim(f"  --- {message['role']} ---"))
                    for line in message["content"].splitlines():
                        c.write(c.dim(f"  {line}"))
                c.write(c.dim(f"  --- ~{estimate_tokens(sent)} tokens of "
                              f"{config.get('runtime.num_ctx')} ---"))
                continue
            if command == "stats":
                current = store.stats()
                c.write(c.dim(f"  {current['total']} entries · {human_bytes(current['db_bytes'])} · "
                              f"pending embeddings: {current['pending']}"))
                continue
            if command == "reset":
                history = []
                session_id = store.create_session()
                c.write(c.dim("  conversation reset"))
                continue
            if command == "memory":
                if argument.strip() == "off":
                    retriever = None
                    c.write(c.dim("  retrieval off"))
                else:
                    retriever = make_retriever(config, store, index, client,
                                               allow_peers=peers_ok)
                    c.write(c.dim("  retrieval on"))
                continue
            c.write(c.yellow(f"  unknown command: /{command}"))
            continue

        trace = getattr(cmd_chat, "_trace", False)
        try:
            if agent_mode:
                # Full agent: gate pre-flight + tool loop. The thinking and
                # gathering phases can't stream, so a spinner covers them; the
                # final answer streams in live, printed as it arrives.
                agent = Agent(config, client, tools, model, knowledge, profile)
                spinner = Spinner(c, "thinking")
                header = (f"{c.green(c.g('dot'))} {c.bold(APP_NAME)}  "
                          if c.color else f"{APP_NAME}> ")
                state = {"answering": False}

                def on_phase(label: str) -> None:
                    if not state["answering"]:
                        spinner.set_label(label)

                def on_text(chunk: str) -> None:
                    if not state["answering"]:
                        state["answering"] = True
                        spinner.stop()
                        c.raw(header)
                    c.raw(chunk)

                on_step = ((lambda name, detail: _print_step(c, name, detail))
                           if trace else None)
                spinner.start()
                try:
                    result = agent.run_streamed(query, history=history, on_text=on_text,
                                                on_phase=on_phase, on_step=on_step)
                finally:
                    if not state["answering"]:
                        spinner.stop()
                if not state["answering"]:
                    # Nothing streamed (edge case); print the whole answer.
                    c.raw(header)
                    c.raw(result.answer)
                c.write("")
                answer = result.answer
                if trace and agent.prefetched is not None:
                    pre = agent.prefetched
                    origin = (f"cache {pre.age_phrase()}" if pre.from_cache else "fetched now")
                    c.write(c.dim(f"  {c.g('bullet')} auto-research("
                                  f"{pre.query[:44]}) [{origin}]"))
                if trace and result.steps:
                    c.write(c.dim("  " + f" {c.g('arrow')} ".join(
                        s["tool"] for s in result.steps)))
            else:
                messages, hits = _prepare_messages(retriever, query, history, days)
                cmd_chat._last_hits = hits  # type: ignore[attr-defined]
                cmd_chat._last_messages = messages  # type: ignore[attr-defined]
                used = estimate_tokens(messages)
                budget = int(config.get("runtime.num_ctx", 8192))
                if used > budget * 0.9:
                    c.write(c.yellow(
                        f"  context is ~{used} tokens against a {budget}-token window; "
                        f"raise runtime.num_ctx or lower retrieval.context_chars"))
                c.raw(f"{c.green(c.g('dot'))} {c.bold(APP_NAME)}  "
                      if c.color else f"{APP_NAME}> ")
                answer = _answer(client, model, messages, c, options=options)
                if hits and args.show_sources:
                    _render_sources(c, hits)
        except KeyboardInterrupt:
            c.write(c.dim(f"\n  {c.g('bullet')} interrupted"))
            continue
        except (OllamaError, MindError) as exc:
            c.write(f"\n  {c.red(c.g('fail'))}  {c.red(str(exc))}")
            continue

        c.write("")
        history.append({"role": "user", "content": query})
        history.append({"role": "assistant", "content": answer})
        store.add_message(session_id, "user", query)
        store.add_message(session_id, "assistant", answer)

    store.close()
    client.close()
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    """One-shot question, suitable for scripts and pipes.

    Same brain as chat: when the model can call tools, this runs the full agent
    — so a world question ("what are the best guns in the finals right now") is
    researched on the web and answered, not deflected back at the user. Falls
    back to plain retrieval only when tools are unavailable or --no-agent/
    --no-memory is given.
    """
    paths = resolve_paths(args)
    config = load_config_or_die(paths)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=False)
    c = CONSOLE
    query = " ".join(args.question).strip()
    if not query:
        raise MindError("no question given")

    want_agent = (not args.no_memory and not getattr(args, "no_agent", False)
                  and bool(config.get("agent.enabled", True)) and not args.show_prompt)
    if want_agent:
        client, store, tools, model, knowledge, profile = _agent_pieces(config, paths, args.model,
                                                      allow_peers=not getattr(args, 'local', False))
        if client.supports_tools(model):
            if not config.get("network.enabled"):
                c.write(c.dim("  (network off — memory tools only; enable with "
                              f"`{APP_NAME} config --set network.enabled=true`)"))
            agent = Agent(config, client, tools, model, knowledge, profile)
            on_step = (lambda name, detail: _print_step(c, name, detail)) if args.trace else None
            try:
                result = agent.run(query, on_step=on_step)
            except ToolsUnsupported:
                result = None
            if result is not None:
                if args.trace and agent.prefetched is not None:
                    pre = agent.prefetched
                    origin = f"cache, {pre.age_phrase()}" if pre.from_cache else "fetched now"
                    c.write(c.dim(f"  · auto-research({pre.query[:50]}) [{origin}]"))
                c.write(result.answer)
                if args.trace and tools.calls:
                    c.write(c.dim("  " + ", ".join(f"{call['tool']}({call['status']})"
                                                   for call in tools.calls)))
                store.close()
                client.close()
                return 0
        # Model cannot call tools: fall back to plain retrieval, reusing the store.
        retriever = tools.retriever
        messages, hits = _prepare_messages(retriever, query, [], args.days)
        _answer(client, model, messages, c, stream=not args.no_stream,
                options=chat_options(config))
        if hits and args.show_sources:
            _render_sources(c, hits)
        store.close()
        client.close()
        return 0

    # --no-agent / --no-memory / --show-prompt: original retrieval-only path.
    client = make_client(config)
    if not client.is_up():
        raise MindError(f"Ollama is not reachable at {config.get('ollama_url')}")
    store = Store(paths.db)
    index = VectorIndex(max_vectors=int(config.get("runtime.max_vectors", 150_000)))
    retriever = (None if args.no_memory else make_retriever(
        config, store, index, client, allow_peers=not getattr(args, "local", False)))
    messages, hits = _prepare_messages(retriever, query, [], args.days)
    if args.show_prompt:
        for message in messages:
            c.write(c.dim(f"--- {message['role']} ---"))
            c.write(c.dim(message["content"]))
        c.write(c.dim(f"--- ~{estimate_tokens(messages)} tokens ---\n"))
    _answer(client, args.model or config.get("chat_model"), messages, c,
            stream=not args.no_stream, options=chat_options(config))
    if hits and args.show_sources:
        _render_sources(c, hits)
    store.close()
    client.close()
    return 0


# ==========================================================================
# Command: search
# ==========================================================================

def cmd_search(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = load_config_or_die(paths, require_setup=False)
    setup_logging(paths, "WARNING", console=False)
    store = Store(paths.db)
    client = make_client(config)
    index = VectorIndex(max_vectors=int(config.get("runtime.max_vectors", 150_000)))
    retriever = make_retriever(config, store, index, client,
                               allow_peers=not getattr(args, "local", False))
    query = " ".join(args.query)
    hits = retriever.retrieve(query, days=args.days, top_k=args.limit)
    c = CONSOLE
    if not hits:
        c.write("No matches.")
        store.close()
        return 0
    if args.json:
        payload = [dataclasses.asdict(hit) for hit in hits]
        c.write(json.dumps(payload, indent=2))
    else:
        c.title(f"{len(hits)} match{'es' if len(hits) != 1 else ''}",
                " ".join(args.query))
        c.write("")
        for rank, hit in enumerate(hits, start=1):
            # A score bar makes relative relevance readable at a glance, which
            # a bare "score 0.871" never is.
            c.write(f"  {c.bold(str(rank).rjust(2))}  {c.bar(max(0.0, min(1.0, hit.score)), 12)}"
                    f"  {c.dim(hit.label())}")
            body = " ".join(hit.text.split())
            c.write(f"      {body[:280]}{'…' if len(body) > 280 else ''}")
            c.write("")
    store.close()
    client.close()
    return 0


# ==========================================================================
# Command: status
# ==========================================================================

def cmd_status(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = Config.load(paths)
    store = Store(paths.db)
    stats = store.stats()
    state, payload = heartbeat_state(paths)
    c = CONSOLE

    if args.json:
        c.write(json.dumps({
            "version": VERSION,
            "home": str(paths.home),
            "daemon": state,
            "heartbeat": payload,
            "config": {
                "chat_model": config.get("chat_model"),
                "embed_model": config.get("embed_model"),
                "retention_days": config.get("retention_days"),
                "sources": config.enabled_sources(),
            },
            "storage": stats,
        }, indent=2, default=str))
        store.close()
        return 0

    dot = c.g("dot")
    daemon_label = {
        "running": c.green(f"{dot} running"),
        "paused": c.yellow(f"{dot} paused"),
        "stale": c.red(f"{dot} not running"),
        "never": c.dim(f"{c.g('ring')} never started"),
    }[state]

    c.title(f"{APP_NAME} {VERSION}", str(paths.home))

    # ---- setup -----------------------------------------------------------
    c.section("setup")
    ollama_up = make_client(config).is_up()
    c.kv("ollama", f"{c.mark(ollama_up)} {config.get('ollama_url')}",
         "" if ollama_up else "unreachable — embeddings and chat will not work")
    c.kv("chat model", config.get("chat_model") or c.yellow("(not set)"))
    c.kv("embed model", config.get("embed_model") or c.yellow("(not set)"))
    c.kv("retention", f"{config.get('retention_days')} days")

    net_on = bool(config.get("network.enabled"))
    c.kv("web access", f"{c.mark(net_on)} " + ("enabled" if net_on
         else c.dim("off — it cannot research anything")))

    enc_marked = is_encrypted(paths.home)
    enc_real = database_looks_encrypted(paths.db)
    if enc_marked and enc_real is not False:
        c.kv("encryption", f"{c.mark(True)} on",
             f"key in {encryption_state(paths.home).get('provider')}")
    else:
        c.kv("encryption", f"{c.mark(False)} " + c.yellow("off"),
             f"database is plaintext — `{APP_NAME} encrypt on`")
    if enc_marked and enc_real is False:
        c.note(c.red("config says encrypted but the file is not — check `encrypt`"))

    auto = autostart_installed(paths)
    c.kv("autostart", f"{c.mark(auto)} " + ("installed" if auto
         else c.dim(f"not installed — `{APP_NAME} install`")))

    known_peers = peer_nodes(config)
    if known_peers or config.get("peers.enabled"):
        federated = bool(config.get("peers.enabled")) and bool(known_peers)
        names = " · ".join(p.name for p in known_peers) or "none configured"
        c.kv("peers", f"{c.mark(federated)} {names}",
             "" if federated else "federation off — `mind peer ping`")

    # ---- capture ---------------------------------------------------------
    c.section("capture")
    c.kv("status", daemon_label)
    if state in ("stale", "never"):
        c.note(f"nothing is being recorded — `{APP_NAME} install` or `{APP_NAME} capture`")
    elif state == "paused":
        c.note(f"recording is off — `{APP_NAME} resume` to continue")

    enabled = config.enabled_sources()
    c.kv("sources", f" {c.g('bullet')} ".join(enabled) if enabled
         else c.yellow("none enabled — nothing will ever be captured"))

    if payload:
        snapshot = payload.get("stats", {})
        c.kv("process", f"pid {payload.get('pid')}",
             f"beat {human_age(float(payload.get('ts', 0)))}")
        if snapshot:
            minutes = int(snapshot.get("uptime_sec", 0) // 60)
            c.kv("uptime", f"{minutes // 60}h {minutes % 60}m" if minutes >= 60
                 else f"{minutes}m")
            c.kv("captured", f"{snapshot.get('captured', 0):,}",
                 f"stored {snapshot.get('stored', 0):,} · queue "
                 f"{payload.get('queue_depth', 0)}")
            dropped = (f"secret {snapshot.get('dropped_secret', 0)} {c.g('bullet')} "
                       f"duplicate {snapshot.get('dropped_duplicate', 0)} "
                       f"{c.g('bullet')} denylist {snapshot.get('dropped_denylist', 0)} "
                       f"{c.g('bullet')} queue-full {snapshot.get('dropped_queue_full', 0)}")
            c.kv("dropped", c.dim(dropped))

    # ---- memory ----------------------------------------------------------
    c.section("memory")
    c.kv("entries", c.bold(f"{stats['total']:,}"))
    if stats["oldest"]:
        days = max(1, int((stats["newest"] - stats["oldest"]) // 86400) or 1)
        c.kv("span", f"{iso(stats['oldest'])} {c.g('arrow')} {iso(stats['newest'])}",
             f"{days} day{'s' if days != 1 else ''}")
        c.kv("last capture", human_age(stats["newest"]))

    total = max(1, stats["total"])
    for source, count in sorted(stats["by_source"].items(), key=lambda kv: -kv[1]):
        share = count / total
        # 4 + 11 + 1 lines the bar up with the value column of kv() above.
        c.write(f"    {c.dim(source.ljust(11))} {c.bar(share)} "
                f"{str(count).rjust(6)}  {c.dim(f'{share * 100:4.0f}%')}")

    if stats["pending"]:
        hint = "waiting for embeddings"
        if not ollama_up:
            hint += " — Ollama is down, they backfill when it returns"
        c.kv("pending", c.yellow(f"{stats['pending']:,}"), hint)

    # Things that exist but were invisible here until now.
    with contextlib.suppress(Exception):
        facts = len(ProfileStore(config, store).facts())
        if facts:
            c.kv("profile", f"{facts} fact{'s' if facts != 1 else ''} learned",
                 f"`{APP_NAME} profile` to read them")
        else:
            c.kv("profile", c.dim("nothing learned yet"))
            # Empty here used to look broken. Say why, and how to force it.
            if stats["total"] < 5:
                c.note("needs more captures first")
            elif state != "running":
                c.note(f"it distils while capture runs — start it, or force a pass "
                       f"now with `{APP_NAME} profile --reflect`")
            else:
                c.note(f"first pass runs within ~15 min of capture starting — "
                       f"or force it: `{APP_NAME} profile --reflect`")
    with contextlib.suppress(Exception):
        known = store.knowledge_stats()
        fresh = known.get("fresh", 0)
        c.kv("researched", f"{fresh} cached answer{'s' if fresh != 1 else ''}",
             f"{known.get('expired', 0)} expired")

    c.kv("size", human_bytes(stats["db_bytes"]),
         f"{'FTS5' if stats['fts'] else 'LIKE fallback'} {c.g('bullet')} "
         f"{'numpy' if HAVE_NUMPY else 'pure python'}")
    c.write("")
    store.close()
    return 0


# ==========================================================================
# Commands: forget / export / reindex / pause / resume / config
# ==========================================================================

def cmd_forget(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    store = Store(paths.db)
    c = CONSOLE
    removed = 0
    if args.all:
        if not args.yes and not prompt_bool("Delete ALL captured data?", False):
            c.write("Cancelled.")
            store.close()
            return 1
        removed = store.delete_all()
        store.vacuum()
    elif args.older_than is not None:
        removed = store.prune(args.older_than, 0)
    elif args.source:
        removed = store.delete_source(args.source)
    elif args.matching:
        removed = store.delete_matching(args.matching)
    else:
        c.write("Specify --all, --older-than DAYS, --source NAME, or --matching TEXT")
        store.close()
        return 2
    c.write(f"Deleted {removed} entr{'y' if removed == 1 else 'ies'}.")
    store.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    store = Store(paths.db)
    since = now_ts() - args.days * 86400 if args.days else None
    out_path = Path(args.out).expanduser() if args.out else None
    handle = open(out_path, "w", encoding="utf-8") if out_path else sys.stdout
    count = 0
    try:
        for row in store.export_rows(since):
            record = {
                "ts": float(row["ts"]),
                "time": datetime.fromtimestamp(row["ts"]).isoformat(timespec="seconds"),
                "source": row["source"],
                "origin": row["origin"],
                "text": row["text"],
                "meta": json.loads(row["meta"] or "{}"),
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            count += 1
    finally:
        if out_path:
            handle.close()
    if out_path:
        CONSOLE.write(f"Exported {count} entries to {out_path}")
    store.close()
    return 0


def cmd_reindex(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = load_config_or_die(paths, require_setup=False)
    store = Store(paths.db)
    client = make_client(config)
    c = CONSOLE
    if not client.is_up():
        raise MindError(f"Ollama is not reachable at {config.get('ollama_url')}")
    if args.all:
        cleared = store.clear_embeddings()
        c.write(f"Cleared {cleared} existing embedding(s).")
    total = store.count_pending()
    if not total:
        c.write("Nothing to embed.")
        store.close()
        return 0
    c.write(f"Embedding {total} entr{'y' if total == 1 else 'ies'} with "
            f"{config.get('embed_model')} …")
    done = 0
    batch_size = max(1, int(config.get("runtime.embed_batch", 16)))
    while True:
        pending = store.pending_embeddings(limit=batch_size)
        if not pending:
            break
        try:
            vectors = client.embed([row["text"] for row in pending], config.get("embed_model"))
        except OllamaError as exc:
            c.write("")
            raise MindError(f"embedding failed: {exc}") from exc
        store.set_embeddings([(int(row["id"]), vec) for row, vec in zip(pending, vectors)])
        done += len(pending)
        c.raw(f"\r  {done}/{total} ({100.0 * done / total:.0f}%)")
    c.write("")
    c.ok("reindex complete")
    store.close()
    client.close()
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Manage indexed folders without hand-writing JSON on a shell command line."""
    paths = resolve_paths(args)
    config = Config.load(paths)
    c = CONSOLE
    folders = list(config.get("sources.files.folders", []))

    if args.clear:
        config.set("sources.files.folders", [])
        config.set("sources.files.enabled", False)
        config.save(paths)
        c.ok("cleared all watch folders and turned file indexing off")
        return 0

    if args.remove:
        wanted = {str(Path(p).expanduser()) for p in args.remove}
        kept = [f for f in folders if f not in wanted and str(Path(f).expanduser()) not in wanted]
        removed = len(folders) - len(kept)
        config.set("sources.files.folders", kept)
        if not kept:
            config.set("sources.files.enabled", False)
        config.save(paths)
        c.ok(f"removed {removed} folder(s)")
        if not kept:
            c.write(c.dim("   file indexing is now off"))
        return 0

    if not args.paths:
        if not folders:
            c.write("No folders are being indexed.")
            c.write(c.dim(f"   add one with: {APP_NAME} watch \"C:/Users/you/Notes\""
                          if IS_WINDOWS else f"   add one with: {APP_NAME} watch ~/Notes"))
            return 0
        enabled = config.get("sources.files.enabled")
        c.write(f"File indexing is {'on' if enabled else c.yellow('off')}. Folders:")
        for folder in folders:
            exists = Path(folder).expanduser().is_dir()
            c.write(f"  {'  ' if exists else c.red('!!')} {folder}"
                    + ("" if exists else c.dim("  (missing)")))
        return 0

    added, rejected = [], []
    for raw in args.paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            resolved = str(path)
            if resolved not in folders:
                folders.append(resolved)
                added.append(resolved)
        else:
            rejected.append(str(path))

    for folder in added:
        c.ok(f"indexing {folder}")
    for folder in rejected:
        c.fail(f"not a folder: {folder}")
    if not folders:
        c.write("Nothing to index.")
        return 1 if rejected else 0

    config.set("sources.files.folders", folders)
    config.set("sources.files.enabled", True)
    config.save(paths)
    c.write("")
    c.write(c.dim(f"   restart capture to pick this up: {APP_NAME} uninstall && {APP_NAME} install"))
    return 1 if rejected else 0


def _agent_pieces(config: Config, paths: Paths, model_override: Optional[str] = None,
                  allow_peers: bool = True):
    """Build everything the agent needs, or raise a user-facing error."""
    client = make_client(config)
    if not client.is_up():
        raise MindError(f"Ollama is not reachable at {config.get('ollama_url')}")
    model = model_override or config.get("chat_model")
    if not client.has_model(model):
        raise MindError(f"model {model!r} is not installed. Run: ollama pull {model}")
    store = Store(paths.db)
    index = VectorIndex(max_vectors=int(config.get("runtime.max_vectors", 150_000)))
    retriever = make_retriever(config, store, index, client, allow_peers=allow_peers)
    web = WebTools(config)
    researcher = DeepResearcher(config, web, client, model)
    knowledge = KnowledgeCache(config, store, web, researcher=researcher)
    tools = ToolBox(config, store, retriever, web, knowledge, researcher=researcher)
    profile = ProfileStore(config, store)
    return client, store, tools, model, knowledge, profile


def _print_step(console: Console, name: str, detail: dict) -> None:
    arguments = detail.get("arguments", {})
    compact = ", ".join(f"{k}={str(v)[:40]}" for k, v in arguments.items())
    console.write(console.dim(f"  · {name}({compact})"))
    preview = (detail.get("result") or "").strip().splitlines()
    if preview:
        console.write(console.dim(f"    -> {preview[0][:100]}"))


def cmd_agent(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = load_config_or_die(paths)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=False)
    c = CONSOLE
    question = " ".join(args.question).strip()
    if not question:
        raise MindError("ask a question")

    client, store, tools, model, knowledge, profile = _agent_pieces(config, paths, args.model,
                                                      allow_peers=not getattr(args, 'local', False))
    if not client.supports_tools(model):
        raise MindError(
            f"{model} does not support tool calling. Try a model that does "
            f"(qwen2.5, llama3.1/3.2, mistral-nemo), or use `{APP_NAME} ask` for plain retrieval.")

    if not config.get("network.enabled"):
        c.write(c.dim("  (network off — memory tools only; "
                      f"enable with `{APP_NAME} config --set network.enabled=true`)"))

    agent = Agent(config, client, tools, model, knowledge, profile)
    on_step = (lambda name, detail: _print_step(c, name, detail)) if args.trace else None
    try:
        result = agent.run(question, on_step=on_step)
    except ToolsUnsupported as exc:
        raise MindError(f"tool calling failed: {exc}")
    if args.trace and agent.prefetched is not None:
        pre = agent.prefetched
        origin = (f"cache, fetched {pre.age_phrase()}" if pre.from_cache else "fetched now")
        c.write(c.dim(f"  · auto-research({pre.query[:50]}) [{origin}]"))
    c.write("")
    c.write(result.answer)
    if args.trace and tools.calls:
        c.write("")
        c.write(c.dim(f"  {len(tools.calls)} tool call(s): "
                      + ", ".join(f"{call['tool']}({call['status']}, {call['ms']}ms)"
                                  for call in tools.calls)))
    store.close()
    client.close()
    return 0


def cmd_tool(args: argparse.Namespace) -> int:
    """Call one agent tool directly, with no model in the loop.

    When something fails, this separates "the tool is broken" from "the model
    did not call it properly" — which are very different problems.
    """
    paths = resolve_paths(args)
    config = load_config_or_die(paths, require_setup=False)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=False)
    c = CONSOLE

    arguments: Dict[str, Any] = {}
    for pair in args.arguments:
        key, sep, value = pair.partition("=")
        if not sep:
            raise MindError(f"expected key=value, got {pair!r}")
        try:
            arguments[key.strip()] = json.loads(value)
        except ValueError:
            arguments[key.strip()] = value

    store = Store(paths.db)
    client = make_client(config)
    retriever = None
    if client.is_up():
        index = VectorIndex(max_vectors=int(config.get("runtime.max_vectors", 150_000)))
        retriever = make_retriever(config, store, index, client,
                                   allow_peers=not getattr(args, "local", False))
    web = WebTools(config)
    researcher = DeepResearcher(config, web, client, config.get("chat_model"))
    tools = ToolBox(config, store, retriever, web, researcher=researcher)

    known = {t["function"]["name"] for t in tools.schema()}
    if args.name not in known:
        c.write(f"Unknown tool {args.name!r}.")
        c.write("Available: " + ", ".join(sorted(known)))
        if not config.get("network.enabled"):
            c.write(c.dim("   (web tools appear once network.enabled is true)"))
        store.close()
        return 2

    started = time.time()
    result = tools.call(args.name, arguments)
    elapsed = (time.time() - started) * 1000
    c.write(result)
    c.write(c.dim(f"\n  {len(result)} chars in {elapsed:.0f} ms"))
    store.close()
    client.close()
    return 1 if result.startswith("ERROR") else 0


def cmd_netcheck(args: argparse.Namespace) -> int:
    """Exercise the network layer against real endpoints, one layer at a time."""
    paths = resolve_paths(args)
    config = load_config_or_die(paths, require_setup=False)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=False)
    c = CONSOLE
    passed = failed = 0

    def report(name: str, ok: bool, detail: str = "") -> None:
        nonlocal passed, failed
        if ok:
            c.ok(f"{name}{('  ' + detail) if detail else ''}")
            passed += 1
        else:
            c.fail(f"{name}  {detail}")
            failed += 1

    c.header(f"{APP_NAME} {VERSION} — network check")

    c.header("Policy (these must refuse)")
    blocked = WebTools(Config({"network": {"enabled": False}}))
    try:
        blocked.fetch_url("https://example.com")
        report("network disabled blocks fetches", False, "it fetched anyway")
    except NetworkDenied:
        report("network disabled blocks fetches", True)
    except MindError as exc:
        report("network disabled blocks fetches", False, str(exc))

    live = WebTools(config)
    for label, url in (("non-http scheme refused", "file:///etc/passwd"),
                       ("missing host refused", "https:///nowhere")):
        try:
            live.fetch_url(url)
            report(label, False, "it was allowed")
        except NetworkDenied:
            report(label, True)
        except MindError as exc:
            report(label, "denied" in str(exc).lower(), str(exc)[:60])

    denied = WebTools(Config({"network": {"enabled": True, "domain_denylist": ["example.com"]}}))
    try:
        denied.fetch_url("https://example.com")
        report("domain denylist blocks fetches", False, "it fetched anyway")
    except NetworkDenied:
        report("domain denylist blocks fetches", True)

    if not config.get("network.enabled"):
        c.write("")
        c.warn("network access is off, so the live checks below are skipped.")
        c.write(f"   Enable with: {APP_NAME} config --set network.enabled=true")
        c.write("")
        c.write(c.green(f"{passed} passed") if not failed else c.red(f"{failed} failed"))
        return 1 if failed else 0

    c.header("Live endpoints")
    try:
        text = live.fetch_url("https://example.com")
        report("plain HTTPS fetch (DNS + TLS + HTML to text)",
               "example domain" in text.lower(), text[:60].replace("\n", " "))
    except MindError as exc:
        report("plain HTTPS fetch (DNS + TLS + HTML to text)", False, str(exc)[:100])

    try:
        article = live.wikipedia(args.topic)
        ok = len(article) > 500 and args.topic.split()[0].lower() in article.lower()
        report(f"wikipedia lookup ({args.topic})", ok, f"{len(article)} chars")
        if ok and args.verbose:
            c.write(c.dim("       " + article[:200].replace("\n", " ") + " ..."))
    except MindError as exc:
        report(f"wikipedia lookup ({args.topic})", False, str(exc)[:100])

    if config.get("network.allow_search", True):
        try:
            results = live.web_search(args.topic)
            report("web search", "http" in results, results.splitlines()[0][:70] if results else "")
        except MindError as exc:
            report("web search", False, str(exc)[:100])
        try:
            digest = live.research(args.topic, max_sources=2)
            opened = "opened 0 of" not in digest and "could not read any" not in digest
            report("research (search + open + read)", opened, digest.splitlines()[0][:80])
            if opened and args.verbose:
                c.write(c.dim("       " + digest[:300].replace("\n", " ") + " ..."))
        except MindError as exc:
            report("research (search + open + read)", False, str(exc)[:100])

        c.header("Search engines (which your network allows)")
        probe = args.topic or "site reliability engineering"
        working = []
        for name in live._enabled_engines():
            try:
                pairs = live._run_engine(name, probe, 5)
                if pairs:
                    working.append(name)
                    c.ok(f"{name}: {len(pairs)} result(s)   e.g. {pairs[0][1][:56]}")
                else:
                    c.warn(f"{name}: reached, but no results parsed (markup may have changed)")
            except MindError as exc:
                c.warn(f"{name}: {str(exc)[:72]}")
        report("at least one web search engine works", bool(working),
               ("using " + ", ".join(working)) if working
               else "all blocked/unparseable — research falls back to Wikipedia")
        if not working:
            c.write(c.dim("       Tip: add a SearXNG instance, e.g."))
            c.write(c.dim(f"       {APP_NAME} config --set "
                          "'network.searxng_instances=[\"https://searx.be\"]'"))

    if args.video:
        try:
            transcript = live.youtube_transcript(args.video)
            report("youtube transcript", len(transcript) > 200, f"{len(transcript)} chars")
        except MindError as exc:
            report("youtube transcript", False, str(exc)[:100])

    c.header("Limits and audit")
    capped = WebTools(Config({"network": {"enabled": True, "max_bytes": 2048}}))
    try:
        # Use the API endpoint the wikipedia check just proved reachable, so a
        # missing article can never masquerade as a broken size cap.
        _, body = capped.fetch_raw(
            "https://en.wikipedia.org/w/api.php?action=query&prop=extracts&explaintext=1"
            "&redirects=1&titles=Wikipedia&format=json")
        report("size cap enforced", len(body) <= 2048 + 512,
               f"{len(body)} bytes from a 2048-byte cap")
    except MindError as exc:
        report("size cap enforced", False, str(exc)[:80])

    report("every fetch logged for audit", len(live.fetch_log) > 0,
           f"{len(live.fetch_log)} request(s) this run")
    if args.verbose:
        for entry in live.fetch_log:
            c.write(c.dim(f"       {entry['status']:<12} {human_bytes(entry['bytes']):>9}  "
                          f"{entry['url'][:70]}"))

    c.write("")
    if failed:
        c.write(c.red(f"{failed} failed, {passed} passed"))
        return 1
    c.write(c.green(f"all {passed} checks passed"))
    return 0


def cmd_websearch(args: argparse.Namespace) -> int:
    """Show, engine by engine, exactly what the web search backends return.

    This is the tool to run when search "doesn't work": it reports whether each
    engine was reachable, how big the page was, which result markers its HTML
    contained, a sample of the raw links found, and what got parsed out — enough
    to see whether the problem is a block or a markup change. With --save it
    writes each engine's raw HTML next to the config so it can be shared."""
    paths = resolve_paths(args)
    config = load_config_or_die(paths, require_setup=False)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=False)
    c = CONSOLE
    if not config.get("network.enabled"):
        c.fail(f"network is off. Enable it first: {APP_NAME} config --set network.enabled=true")
        return 1

    web = WebTools(config)
    query = args.query
    c.header(f"{APP_NAME} {VERSION} — web search debug — {query!r}")
    configured = config.get("network.search_engines", None)
    resolved = web._enabled_engines()
    c.write(c.dim(f"   configured: {configured!r}"))
    c.write(c.dim(f"   will try:   {', '.join(resolved)}"))
    if isinstance(configured, str):
        c.warn("   network.search_engines is a STRING, not a list — your shell stripped the "
               "quotes off the JSON. Using the built-in order instead (search still works).")
        c.write(c.dim("   to set it properly in PowerShell, use single quotes around the JSON:"))
        c.write(c.dim(f"""   {APP_NAME} config --set 'network.search_engines=["bing","duckduckgo-lite"]'"""))
    specs = web._engine_specs()
    any_results = False

    for name in web._enabled_engines():
        if name not in specs:
            continue
        build_url, parse = specs[name]
        url = build_url(query)
        previous_ua = web.user_agent
        try:
            web.user_agent = str(config.get("network.search_user_agent", web.SEARCH_UA))
            _, body = web.fetch_raw(url, headers=web.SEARCH_HEADERS)
        except MindError as exc:
            c.write("")
            c.fail(f"{name}: {str(exc)[:90]}")
            continue
        finally:
            web.user_agent = previous_ua

        parsed = web._run_engine(name, query, 8)
        any_results = any_results or bool(parsed)
        c.write("")
        c.write(c.bold(name) if hasattr(c, "bold") else name)
        c.write(c.dim(f"   {len(body):,} bytes fetched"))
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.S | re.I)
        if title:
            c.write(c.dim("   title: " + re.sub(r"\s+", " ", title.group(1)).strip()[:76]))
        markers = {m: len(re.findall(re.escape(m), body)) for m in
                   ("result__a", "result-link", "uddg=", "b_algo", "<h2", 'class="ob"',
                    "class='ob'", "results-standard", "result-title")}
        present = ", ".join(f"{k}={v}" for k, v in markers.items() if v)
        c.write(c.dim(f"   total <a>: {len(re.findall(r'<a[ >]', body))}   "
                      f"markers: {present or '(none of the known ones)'}"))
        blocked = any(w in body.lower() for w in
                      ("captcha", "unusual traffic", "are you a robot", "challenge-form"))
        if blocked:
            c.warn("   looks like a challenge/anti-bot page")
        sample = 0
        for _attrs, href, text in web._iter_anchors(body):
            if sample >= 6:
                break
            c.write(c.dim(f"     a  {href[:64]:<64}  {text[:32]}"))
            sample += 1
        if parsed:
            for i, (t, u) in enumerate(parsed[:5], 1):
                c.write(f"     [{i}] {u[:64]:<64}  {t[:32]}")
        else:
            c.warn("   parsed 0 results from this engine")
            # The page clearly HAS results (it carries their markers) but the
            # parser missed them. Print the real markup around the first result
            # so the mismatch is fixable from this output alone.
            if present and not blocked:
                for marker in ("b_algo", "result__a", "result-link", "results-standard",
                               "result-title", "<h2"):
                    index = body.find(marker)
                    if index == -1:
                        continue
                    excerpt = re.sub(r"\s+", " ", body[max(0, index - 140): index + 760])
                    c.write(c.dim(f"   markup around the first {marker!r} "
                                  f"(paste this to fix the parser):"))
                    c.write(c.dim("   " + excerpt))
                    break
        if args.save:
            safe = name.replace(":", "_").replace("/", "_").replace(".", "_")
            out = paths.home / f"search-{safe}.html"
            with contextlib.suppress(OSError):
                out.write_text(body, encoding="utf-8")
                c.write(c.dim(f"   raw HTML saved: {out}"))

    c.write("")
    if any_results:
        c.write(c.green("At least one engine parsed results. If they look wrong, share the "
                        "saved HTML (run again with --save) and I can fix the parser."))
    else:
        c.write(c.red("No engine parsed any results. The markers above show whether it is a "
                      "block or a markup change. Run again with --save and share a file."))
    return 0 if any_results else 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Answer questions from other machines you own. Read-only, one port."""
    paths = resolve_paths(args)
    config = load_config_or_die(paths, require_setup=False)
    setup_logging(paths, config.get("runtime.log_level", "INFO"), console=args.verbose)
    c = CONSOLE

    host = args.host or str(config.get("peers.serve_host", "127.0.0.1"))
    port = int(args.port or config.get("peers.serve_port", 7717))
    token = str(config.get("peers.token") or "").strip()
    node = local_node_name(config)

    server = build_peer_server(config, paths, host=host, port=port)
    bound_host, bound_port = server.server_address[0], server.server_address[1]

    c.title(f"{APP_NAME} peer", f"v{VERSION}")
    c.kv("node", node)
    c.kv("listening", f"{bound_host}:{bound_port}")
    c.kv("token", c.green("set") if token else c.yellow("none"),
         "" if token else "loopback only")
    entries = server.ping_payload().get("entries")
    if entries is not None:
        c.kv("serving", f"{entries:,} " + ("entry" if entries == 1 else "entries"))
    c.rule()

    if is_loopback_host(bound_host):
        c.note("Loopback only — reach this machine over Tailscale or")
        c.note("WireGuard and the port is never exposed at all.")
    else:
        c.warn(f"Listening on {bound_host} — anything that can reach this port and "
               f"holds the token can query everything captured here.")
    c.write(c.dim("Ctrl+C to stop."))
    c.write()

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        c.write()
        c.write(c.dim("stopped"))
    finally:
        with contextlib.suppress(Exception):
            server.shutdown()
        with contextlib.suppress(Exception):
            server.server_close()
    return 0


def _print_peer_table(c: Console, peers: Sequence[Peer], statuses: Dict[str, str]) -> None:
    width = max([len(p.name) for p in peers] + [4])
    for peer in peers:
        state = statuses.get(peer.name, "")
        c.write(f"  {peer.name.ljust(width)}  {c.dim(peer.url)}"
                + (f"  {state}" if state else ""))


def cmd_peer(args: argparse.Namespace) -> int:
    """Manage the other machines this one can ask."""
    paths = resolve_paths(args)
    config = Config.load(paths)
    setup_logging(paths, "WARNING", console=False)
    c = CONSOLE

    def save() -> None:
        problems = config.validate()
        if problems:
            raise ConfigError("refusing to save:\n  - " + "\n  - ".join(problems))
        config.save(paths)

    nodes = list(config.get("peers.nodes", []) or [])
    if isinstance(nodes, str):          # shell-mangled; rebuild from parsed peers
        nodes = [dataclasses.asdict(p) for p in peer_nodes(config)]

    # -- token -------------------------------------------------------------
    if args.action == "token":
        if args.new:
            token = new_peer_token()
            config.set("peers.token", token)
            save()
            c.ok("new mesh token generated")
            c.write()
            c.write(f"  {token}")
            c.write()
            c.note("Set the SAME token on every machine in this mesh:")
            c.sub(f"mind config --set peers.token={token}")
            return 0
        token = str(config.get("peers.token") or "")
        if not token:
            c.warn("no token set — run `mind peer token --new`")
            return 1
        c.write(token)
        return 0

    # -- add ---------------------------------------------------------------
    if args.action == "add":
        if not args.url:
            raise MindError("usage: mind peer add <name> <url>")
        candidate = _coerce_node({"name": args.name, "url": args.url,
                                  "token": args.token or ""})
        if candidate is None:
            raise MindError(f"not a usable peer address: {args.url!r}")
        nodes = [n for n in nodes
                 if not (isinstance(n, dict) and n.get("name") == candidate.name)]
        entry: Dict[str, Any] = {"name": candidate.name, "url": candidate.url}
        if args.token:
            entry["token"] = args.token
        nodes.append(entry)
        config.set("peers.nodes", nodes)
        if not config.get("peers.enabled"):
            config.set("peers.enabled", True)
            c.write(c.dim("  federated query enabled"))
        save()
        c.ok(f"added {candidate.name} → {candidate.url}")
        if not config.get("peers.token") and not args.token:
            c.warn("no token set yet — run `mind peer token --new` on one machine "
                   "and set the same value on the others")
        c.sub("check it: mind peer ping")
        return 0

    # -- remove ------------------------------------------------------------
    if args.action == "remove":
        before = len(nodes)
        kept = []
        for n in nodes:
            peer = _coerce_node(n)
            if peer is not None and (peer.name == args.name or peer.url == args.name):
                continue
            kept.append(n)
        if len(kept) == before:
            c.warn(f"no peer called {args.name!r}")
            return 1
        config.set("peers.nodes", kept)
        if not kept:
            config.set("peers.enabled", False)
        save()
        c.ok(f"removed {args.name}")
        return 0

    # -- ping / list -------------------------------------------------------
    peers = peer_nodes(config)
    enabled = bool(config.get("peers.enabled"))
    c.title(f"{APP_NAME} peers", "federated query")
    c.kv("this node", local_node_name(config))
    c.kv("federation", c.green("on") if enabled else c.yellow("off"),
         "" if enabled else "results come from this machine only")
    c.kv("token", c.green("set") if config.get("peers.token") else c.red("none"))
    c.rule()

    if not peers:
        c.write("  No peers configured.")
        c.write()
        c.note("On the other machine:")
        c.sub("mind serve")
        c.note("Then here:")
        c.sub("mind peer add laptop http://laptop:7717")
        return 0

    if args.action != "ping":
        _print_peer_table(c, peers, {})
        c.write()
        c.sub("mind peer ping   — check they answer")
        return 0

    client = PeerClient(config)
    statuses: Dict[str, str] = {}
    reachable = 0
    for peer in peers:
        try:
            info = client.ping(peer)
        except PeerError as exc:
            statuses[peer.name] = c.red(str(exc).split(": ", 1)[-1])
            continue
        reachable += 1
        entries = info.get("entries")
        detail = (f"{entries:,} " + ("entry" if entries == 1 else "entries")
                  if isinstance(entries, int) else "up")
        statuses[peer.name] = c.green(f"{c.g('ok')} {detail}")
    _print_peer_table(c, peers, statuses)
    c.write()
    word = "peer" if len(peers) == 1 else "peers"
    if reachable == len(peers):
        c.ok(f"{reachable} {word} answering")
    elif reachable:
        c.warn(f"{reachable} of {len(peers)} peers answering")
    else:
        c.fail("no peers answering")
        c.note("Usual causes: the other machine isn't running `mind serve`, the "
               "token differs, or the address isn't reachable from here.")
    return 0 if reachable else 1


def cmd_encrypt(args: argparse.Namespace) -> int:
    """Turn database encryption on or off, or report where it stands."""
    paths = resolve_paths(args)
    load_config_or_die(paths, require_setup=False)
    setup_logging(paths, "WARNING", console=False)
    c = CONSOLE
    state = encryption_state(paths.home)
    action = getattr(args, "action", "status") or "status"

    if action == "status":
        marked = bool(state.get("enabled"))
        on_disk = database_looks_encrypted(paths.db)
        c.title(f"{APP_NAME} {VERSION}", "encryption")

        c.section("at rest")
        # Report what the FILE says, not just what the marker claims.
        if on_disk is None:
            c.kv("database", c.dim("none yet"), str(paths.db))
        elif on_disk:
            c.kv("database", f"{c.mark(True)} encrypted", "no SQLite header on disk")
        else:
            c.kv("database", f"{c.mark(False)} " + c.yellow("plaintext"),
                 "starts with 'SQLite format 3'")
        c.kv("key", f"{state.get('provider')}" if marked else c.dim("none"))
        c.kv("config says", "encrypted" if marked else c.dim("not encrypted"))
        if on_disk is not None and marked != on_disk:
            c.write("")
            c.fail("MISMATCH between config and the actual file — do not trust "
                   "this state; re-run `encrypt on` / `encrypt off`.")

        c.section("the rest of the picture")
        fde_on, fde_text = disk_encryption_status()
        c.kv("full disk", f"{c.mark(fde_on)} {fde_text}")
        if fde_on is not True:
            c.note("this matters more than the above for a lost or stolen machine")
        c.kv("sqlcipher3", f"{c.mark(HAVE_SQLCIPHER)} " +
             ("installed" if HAVE_SQLCIPHER else c.dim("not installed")))

        stray = Path(str(paths.db) + ".plaintext-backup")
        if stray.exists():
            c.write("")
            c.fail(f"an UNENCRYPTED backup is still here: {stray}")
            c.sub("while it exists, encryption buys you nothing — delete it "
                  "once you have confirmed things work.")
        if not marked:
            c.write("")
            c.write(f"  {c.g('arrow')} turn it on:  {c.bold(APP_NAME + ' encrypt on')}")
        c.write("")
        return 0

    if action == "off":
        if not state.get("enabled"):
            c.write("Not encrypted; nothing to do.")
            return 0
        c.warn("This writes the database back to disk in PLAINTEXT.")
        if not args.yes and not prompt_bool("Decrypt the database?", False):
            c.write("Cancelled.")
            return 1
        result = decrypt_database(paths, progress=lambda m: c.write(c.dim(f"   {m}")))
        c.ok(f"decrypted {result['rows']} row(s); encryption is off")
        return 0

    # action == "on"
    if state.get("enabled"):
        c.write(f"Already encrypted (key: {state.get('provider')}).")
        return 0
    if not HAVE_SQLCIPHER:
        c.fail(SQLCIPHER_MISSING)
        return 1

    provider_name = args.provider or default_provider_name()
    provider = make_provider(provider_name, paths)
    if not provider.available():
        c.fail(f"the {provider_name!r} key store is not available on this machine")
        return 1

    c.header(f"Encrypting with the {provider_name!r} key store")
    c.write(c.dim(f"   {provider.description}"))
    if not provider.unattended:
        c.warn("   capture will NOT be able to start unattended — you will be")
        c.warn("   prompted for the passphrase every time it runs.")
    c.warn("   If you lose this key, the data is gone. There is no recovery.")
    c.write("")
    if not args.yes and not prompt_bool("Encrypt the database now?", False):
        c.write("Cancelled.")
        return 1

    # A paused daemon is still a live process holding the database open, and
    # Windows refuses to rename a file with any open handle — so "paused" has
    # to block here too, not just "running".
    daemon_state = heartbeat_state(paths)[0]
    if daemon_state in ("running", "paused"):
        c.fail(f"the capture daemon is {daemon_state} and holds the database open.")
        c.write(f"   `{APP_NAME} pause` is not enough — the process must exit.")
        c.write("   End python.exe/pythonw.exe running mind.py (Task Manager > Details),")
        c.write(f"   then run `{APP_NAME} encrypt on` again.")
        return 1
    if daemon_state == "stale":
        c.warn("a capture daemon may still be running (its heartbeat is stale).")
        c.write(c.dim("   If this fails with a file-in-use error, stop it and retry."))

    result = encrypt_database(paths, provider, progress=lambda m: c.write(c.dim(f"   {m}")))
    c.write("")
    c.ok(f"encrypted {result['rows']} row(s) with the {result['provider']} key")
    if result.get("backup"):
        c.warn(f"plaintext backup kept at: {result['backup']}")
        c.sub("verify things work, then DELETE that file — it is unencrypted.")
    return 0


def cmd_knowledge(args: argparse.Namespace) -> int:
    """Inspect and manage the short-lived cache of things looked up online."""
    paths = resolve_paths(args)
    load_config_or_die(paths, require_setup=False)   # validates before touching the db
    store = Store(paths.db)
    c = CONSOLE

    if args.forget is not None:
        removed = store.knowledge_forget(args.forget or None)
        c.ok(f"forgot {removed} cached answer(s)")
        store.close()
        return 0
    if args.prune:
        removed = store.knowledge_prune()
        c.ok(f"pruned {removed} expired entr{'y' if removed == 1 else 'ies'}")
        store.close()
        return 0

    stats = store.knowledge_stats()
    rows = store.knowledge_list(include_expired=args.all)
    c.header(f"{APP_NAME} knowledge cache")
    c.write(f"  {stats['fresh']} fresh, {stats['expired']} expired, "
            f"{stats['hits']} cache hit(s) saved a refetch")
    if not rows:
        c.write(c.dim("\n  Nothing cached yet. It fills as questions get researched."))
        store.close()
        return 0
    c.write("")
    for row in rows:
        remaining = row["expires_at"] - now_ts()
        life = (f"expires in {int(remaining // 3600)}h" if remaining > 3600
                else f"expires in {max(0, int(remaining // 60))}m" if remaining > 0
                else c.dim("EXPIRED"))
        c.write(f"  {c.bold(row['query'][:64])}")
        c.write(c.dim(f"    {row['category']} · fetched {human_age(row['fetched_at'])} · "
                      f"{life} · {row['hits']} hit(s)"))
        if args.verbose:
            first = row["answer"].strip().splitlines()
            if first:
                c.write(c.dim(f"    {first[0][:100]}"))
    store.close()
    return 0


def _human_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"


def cmd_screentime(args: argparse.Namespace) -> int:
    """Summarise time spent per app/game from focus capture."""
    paths = resolve_paths(args)
    load_config_or_die(paths, require_setup=False)
    store = Store(paths.db)
    c = CONSOLE

    now = now_ts()
    if args.expr:
        resolved = resolve_time_expression(" ".join(args.expr))
        if not resolved:
            raise MindError(f"couldn't understand the time {' '.join(args.expr)!r}")
        start, end, label = resolved
    else:
        start, end = now - args.days * 86400, now
        label = f"last {args.days} day(s)"

    usage = store.app_usage(start, end, limit=args.limit)
    if not usage:
        c.write(f"No app/window activity captured for {label}.")
        c.write(c.dim(f"  (enable it with `{APP_NAME} config --set sources.focus.enabled=true`)"))
        store.close()
        return 0

    total = sum(e["seconds"] for e in usage)
    c.header(f"screen time — {label}")
    c.write(c.dim(f"  {_human_duration(total)} across {len(usage)} app(s)\n"))
    longest = max(e["seconds"] for e in usage) or 1
    for entry in usage:
        bar_len = int(18 * entry["seconds"] / longest)
        bar = "█" * bar_len + "·" * (18 - bar_len)
        c.write(f"  {entry['app'][:22]:<22} {c.dim(bar)} "
                f"{_human_duration(entry['seconds']):>8}  {c.dim(str(entry['sessions']) + ' sess')}")
    store.close()
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    """Show, add to, reflect, or forget the durable profile of the user."""
    paths = resolve_paths(args)
    config = load_config_or_die(paths, require_setup=False)
    setup_logging(paths, "WARNING", console=False)
    store = Store(paths.db)
    profile = ProfileStore(config, store)
    c = CONSOLE

    if args.forget is not None:
        removed = store.profile_forget(args.forget or None)
        c.ok(f"forgot {removed} fact(s)")
        store.close()
        return 0

    if args.add:
        client = make_client(config)
        reflector = Reflector(config, store, client, profile)
        try:
            added = reflector.add_manual(" ".join(args.add), category=args.category or "general")
        except MindError as exc:
            c.write(c.red(f"  {exc}"))
            store.close()
            return 1
        c.ok("added to your profile" if added else "reinforced an existing fact")
        store.close()
        client.close()
        return 0

    if args.reflect:
        config_full = load_config_or_die(paths)  # needs a chat model
        client = make_client(config_full)
        if not client.is_up():
            raise MindError(f"Ollama is not reachable at {config_full.get('ollama_url')}")
        reflector = Reflector(config_full, store, client, profile)
        c.write(c.dim("  reflecting on recent activity …"))
        summary = reflector.reflect(force=args.force)
        if summary.get("error"):
            c.fail(f"reflection failed: {summary['error']}")
            store.close()
            return 1
        c.ok(f"{summary['added']} new fact(s), {summary['reinforced']} reinforced "
             f"from {summary['observations']} observation(s)")
        if summary["skipped_sensitive"]:
            c.write(c.dim(f"  ({summary['skipped_sensitive']} sensitive inference(s) dropped "
                          f"by the firewall)"))
        if summary["observations"] == 0:
            c.write(c.dim("  no new activity since the last reflection"))
        store.close()
        client.close()
        return 0

    facts = profile.facts()
    if args.json:
        payload = [{"text": f.text, "category": f.category, "source": f.source,
                    "confidence": round(f.effective, 2)} for f in facts]
        c.write(json.dumps(payload, indent=2))
        store.close()
        return 0

    c.header(f"{APP_NAME} — what it has learned about you")
    if not facts:
        c.write(c.dim("  Nothing yet. It builds up as the daemon reflects on your activity"))
        c.write(c.dim(f"  each night, or run `{APP_NAME} profile --reflect` to do it now."))
        store.close()
        return 0

    by_cat: Dict[str, List[ProfileFact]] = {}
    for fact in facts:
        by_cat.setdefault(fact.category, []).append(fact)
    order = [x for x in PROFILE_CATEGORIES if x in by_cat] + \
            [x for x in by_cat if x not in PROFILE_CATEGORIES]
    for category in order:
        c.write("")
        c.write(c.bold(f"  {category}"))
        for fact in by_cat[category]:
            tag = c.dim(" ✎") if fact.source == "manual" else ""
            c.write(f"    {c.dim(fact.confidence_bar())} {fact.text}{tag}")
            if args.why:
                c.write(c.dim(f"        last seen {human_age(fact.updated_at)} · "
                              f"confidence {fact.effective:.1f}"))
    c.write("")
    c.write(c.dim(f"  {len(facts)} fact(s). ✎ = added by you. "
                  f"Forget one with `{APP_NAME} profile --forget \"text\"`."))
    store.close()
    return 0


def autostart_installed(paths: Paths) -> bool:
    """True when a logon entry exists that can restart capture for us."""
    if IS_WINDOWS:
        result = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME],
                                capture_output=True, text=True)
        return result.returncode == 0
    if IS_MACOS:
        return (Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_LABEL}.plist").exists()
    return (Path.home() / ".config" / "systemd" / "user" / "mind-capture.service").exists()


def start_installed_capture(paths: Paths) -> Tuple[bool, str]:
    """Ask the platform's service manager to start capture. (ok, detail)."""
    try:
        if IS_WINDOWS:
            result = subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME],
                                    capture_output=True, text=True)
        elif IS_MACOS:
            result = subprocess.run(
                ["launchctl", "kickstart", "-k", f"gui/{os.getuid()}/{LAUNCH_LABEL}"],
                capture_output=True, text=True)
        else:
            result = subprocess.run(
                ["systemctl", "--user", "start", "mind-capture.service"],
                capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    detail = (result.stderr or result.stdout or "").strip()
    return result.returncode == 0, detail


def cmd_pause(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    c = CONSOLE
    # Read the daemon state BEFORE writing the flag: heartbeat_state() reports
    # "paused" whenever the flag exists, so checking afterwards would always
    # look like a live process, even with nothing running.
    state = heartbeat_state(paths)[0]
    paths.paused.write_text(datetime.now().isoformat(timespec="seconds"), encoding="utf-8")
    c.write("Capture paused. Nothing will be recorded until you run `resume`.")
    if state not in ("running", "paused"):
        c.warn("(no capture process was running anyway)")
    else:
        c.write(c.dim("   The process keeps running, it just stops recording — so it "
                      "still holds the database open."))
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    """Clear the pause flag and make sure capture is actually running again.

    Clearing the flag alone is not enough: if the process was stopped (or
    killed, say to encrypt the database) there is nothing left to un-pause, and
    reporting "resumed" would be a lie.
    """
    paths = resolve_paths(args)
    c = CONSOLE
    with contextlib.suppress(OSError):
        paths.paused.unlink()

    if heartbeat_state(paths)[0] == "running":
        c.ok("Capture resumed.")
        return 0

    # Nothing is running. Try to start it through whatever was installed.
    if autostart_installed(paths):
        c.write(c.dim("   no capture process was running — starting it"))
        ok, detail = start_installed_capture(paths)
        if ok:
            for _ in range(20):  # give the daemon a moment to write a heartbeat
                time.sleep(0.5)
                if heartbeat_state(paths)[0] == "running":
                    c.ok("Capture resumed and running.")
                    return 0
            c.warn("started it, but no heartbeat yet — check `status` in a few seconds.")
            return 0
        c.fail(f"could not start the capture service: {detail[:160]}")
    else:
        c.warn("pause flag cleared, but no capture process is running.")
        c.write(c.dim("   Nothing is being recorded right now."))

    c.write("")
    c.write("   Start it one of these ways:")
    c.write(f"     {APP_NAME} install     # run automatically at logon (recommended)")
    c.write(f"     {APP_NAME} capture     # run in this window, foreground")
    return 1


def cmd_config(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    config = Config.load(paths)
    c = CONSOLE
    if args.path:
        c.write(str(paths.config))
        return 0
    if args.set:
        for assignment in args.set:
            key, sep, raw = assignment.partition("=")
            if not sep:
                raise MindError(f"expected key=value, got {assignment!r}")
            key = key.strip()
            try:
                value: Any = json.loads(raw)
            except ValueError:
                value = raw
            value = coerce_config_value(key, value, config.get(key))
            config.set(key, value)
            c.write(f"  {key} = {json.dumps(value)}")
            if key == "sources.files.folders":
                for folder in value:
                    if not Path(folder).expanduser().is_dir():
                        c.warn(f"{folder} does not exist — it will be skipped until it does")
        problems = config.validate()
        if problems:
            raise ConfigError("refusing to save:\n  - " + "\n  - ".join(problems))
        config.save(paths)
        c.ok(f"saved {paths.config}")
        return 0
    if args.get:
        c.write(json.dumps(config.get(args.get), indent=2))
        return 0
    c.write(json.dumps(config.data, indent=2))
    return 0


# ==========================================================================
# Commands: install / uninstall
# ==========================================================================

TASK_NAME = "MindCapture"
LAUNCH_LABEL = "com.mind.capture"


def _script_path() -> str:
    return str(Path(__file__).resolve())


def _python_for_background() -> str:
    executable = Path(sys.executable)
    if IS_WINDOWS:
        candidate = executable.with_name("pythonw.exe")
        if candidate.exists():
            return str(candidate)
    return str(executable)


def _launch_plist(paths: Paths, python: str, script: str, home_flag: List[str]) -> str:
    """Build the LaunchAgent plist. ProcessType Interactive keeps App Nap from
    throttling our polling timers when the daemon sits in the background."""
    program_args = "".join(
        f"    <string>{value}</string>\n"
        for value in [python, script] + home_flag + ["capture", "--quiet"])
    env_block = ""
    if os.environ.get("MIND_HOME"):
        env_block = ('  <key>EnvironmentVariables</key>\n  <dict>\n'
                     f'    <key>MIND_HOME</key><string>{paths.home}</string>\n'
                     '  </dict>\n')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n<dict>\n'
        f'  <key>Label</key><string>{LAUNCH_LABEL}</string>\n'
        f'  <key>ProgramArguments</key>\n  <array>\n{program_args}  </array>\n'
        f'{env_block}'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key><true/>\n'
        '  <key>ProcessType</key><string>Interactive</string>\n'
        f'  <key>WorkingDirectory</key><string>{Path(script).parent}</string>\n'
        f'  <key>StandardOutPath</key><string>{paths.home / "launchd.out.log"}</string>\n'
        f'  <key>StandardErrorPath</key><string>{paths.home / "launchd.err.log"}</string>\n'
        '</dict>\n</plist>\n')


def _install_macos(paths: Paths, c: Console, python: str, script: str,
                   home_flag: List[str]) -> int:
    plist_dir = Path.home() / "Library" / "LaunchAgents"
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / f"{LAUNCH_LABEL}.plist"
    plist_path.write_text(_launch_plist(paths, python, script, home_flag), encoding="utf-8")

    domain = f"gui/{os.getuid()}"
    target = f"{domain}/{LAUNCH_LABEL}"

    # `launchctl load` is deprecated; bootstrap/bootout is the modern pair, with
    # a fallback for older systems where bootstrap is unavailable.
    subprocess.run(["launchctl", "bootout", target], capture_output=True)
    result = subprocess.run(["launchctl", "bootstrap", domain, str(plist_path)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        legacy = subprocess.run(["launchctl", "load", "-w", str(plist_path)],
                                capture_output=True, text=True)
        if legacy.returncode != 0:
            c.fail("launchctl refused the agent:")
            c.write("   " + (result.stderr or result.stdout).strip())
            c.write(f"\n   Start it by hand instead:\n   {python} {script} capture")
            return 1
    subprocess.run(["launchctl", "kickstart", "-k", target], capture_output=True)
    c.ok(f"launch agent installed and started: {plist_path}")

    c.write("")
    c.warn("macOS permissions are granted per binary, and launchd runs a different one")
    c.write("   than your terminal did. If focus capture goes quiet after installing, open")
    c.write("   System Settings > Privacy & Security and add this binary:")
    c.write(f"     {python}")
    c.write("   under Accessibility (window titles) and Automation > System Events.")
    c.write("   Indexing folders under Desktop/Documents/Downloads additionally needs")
    c.write("   Full Disk Access for that same binary.")
    c.write(c.dim(f"\n   remove later with: {APP_NAME} uninstall"))
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    load_config_or_die(paths)  # fail early if not configured
    c = CONSOLE
    python = _python_for_background()
    script = _script_path()
    home_flag = ["--home", str(paths.home)] if os.environ.get("MIND_HOME") else []

    if IS_WINDOWS:
        command = subprocess.list2cmdline([python, script] + home_flag + ["capture", "--quiet"])
        result = subprocess.run(
            ["schtasks", "/Create", "/SC", "ONLOGON", "/TN", TASK_NAME,
             "/TR", command, "/RL", "LIMITED", "/F"],
            capture_output=True, text=True)
        if result.returncode != 0:
            c.fail("could not register the scheduled task:")
            c.write("   " + (result.stderr or result.stdout).strip())
            c.write(f"\n   Run this manually instead:\n   {command}")
            return 1
        c.ok(f"scheduled task '{TASK_NAME}' created (starts at logon)")
        subprocess.run(["schtasks", "/Run", "/TN", TASK_NAME], capture_output=True)
        c.ok("capture started")
        c.write(c.dim(f"   remove later with: {APP_NAME} uninstall"))
        return 0

    if IS_MACOS:
        return _install_macos(paths, c, python, script, home_flag)

    if shutil.which("systemctl"):
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit_path = unit_dir / "mind-capture.service"
        exec_start = " ".join([python, script] + home_flag + ["capture", "--quiet"])
        unit_path.write_text(
            "[Unit]\nDescription=mind capture daemon\nAfter=graphical-session.target\n\n"
            "[Service]\nType=simple\n"
            f"ExecStart={exec_start}\nRestart=on-failure\nRestartSec=10\n\n"
            "[Install]\nWantedBy=default.target\n", encoding="utf-8")
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        result = subprocess.run(["systemctl", "--user", "enable", "--now", "mind-capture.service"],
                                capture_output=True, text=True)
        if result.returncode != 0:
            c.fail(f"systemctl failed: {result.stderr.strip()}")
            return 1
        c.ok(f"systemd user service installed and started: {unit_path}")
        return 0

    c.warn("no supported service manager found. Add this to your startup:")
    c.write("   " + " ".join([python, script] + home_flag + ["capture", "--quiet"]))
    return 1


def cmd_uninstall(args: argparse.Namespace) -> int:
    c = CONSOLE
    if IS_WINDOWS:
        result = subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
                                capture_output=True, text=True)
        if result.returncode == 0:
            c.ok(f"removed scheduled task '{TASK_NAME}'")
            return 0
        c.warn((result.stderr or result.stdout).strip() or "task not found")
        return 1
    if IS_MACOS:
        plist_path = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_LABEL}.plist"
        target = f"gui/{os.getuid()}/{LAUNCH_LABEL}"
        booted_out = subprocess.run(["launchctl", "bootout", target], capture_output=True)
        if booted_out.returncode != 0:
            subprocess.run(["launchctl", "unload", "-w", str(plist_path)], capture_output=True)
        with contextlib.suppress(OSError):
            plist_path.unlink()
        c.ok("launch agent removed")
        return 0
    unit_path = Path.home() / ".config" / "systemd" / "user" / "mind-capture.service"
    subprocess.run(["systemctl", "--user", "disable", "--now", "mind-capture.service"],
                   capture_output=True)
    with contextlib.suppress(OSError):
        unit_path.unlink()
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    c.ok("systemd user service removed")
    return 0


# ==========================================================================
# Built-in test suite
# ==========================================================================

class _FakeClient:
    """Deterministic stand-in for OllamaClient used by selftest."""

    DIM = 64

    def __init__(self) -> None:
        self.calls = 0
        self.fail = False

    @staticmethod
    def _vector(text: str) -> List[float]:
        vec = [0.0] * _FakeClient.DIM
        for token in re.findall(r"[a-z0-9]+", text.lower()):
            digest = hashlib.sha1(token.encode()).digest()
            vec[digest[0] % _FakeClient.DIM] += 1.0
        if not any(vec):
            vec[0] = 1.0
        return vec

    def embed(self, texts, model=None):
        self.calls += 1
        if self.fail:
            raise OllamaError("simulated outage")
        return [self._vector(t) for t in texts]

    def embed_one(self, text, model=None):
        return self.embed([text])[0]

    def is_up(self):
        return not self.fail


def _selftest_cases() -> List[Tuple[str, Callable[[Path], None]]]:
    def test_chunking(_tmp: Path) -> None:
        assert chunk_text("") == []
        assert chunk_text("short") == ["short"]
        chunks = chunk_text("word " * 2000, size=500, overlap=50)
        assert len(chunks) > 5
        assert all(len(c) <= 520 for c in chunks), [len(c) for c in chunks[:5]]
        joined = chunk_text("para one.\n\npara two.\n\npara three.", size=20, overlap=5)
        assert joined, "expected chunks"

    def test_redaction(_tmp: Path) -> None:
        red = Redactor()
        assert red.reason("sk-abcdefghijklmnopqrstuvwxyz012345") is not None
        assert red.reason("-----BEGIN RSA PRIVATE KEY-----") == "private-key"
        assert red.reason("password = hunter2hunter2") is not None
        assert red.reason("AKIAIOSFODNN7EXAMPLE") is not None
        assert red.reason("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123") is not None
        assert red.reason("lunch with priya at 1pm, discuss the k8s rollout") is None
        assert red.reason("meeting notes: ship the detection rules by friday") is None
        # Long non-secret numbers should not trip the card rule unless Luhn-valid.
        assert red.reason("order 1234567890123456789 shipped") is None
        assert luhn_valid("4111111111111111") is True
        assert luhn_valid("1234567812345678") is False

    def test_vector_pack(_tmp: Path) -> None:
        blob, bits, dim = pack_vector([3.0, 4.0, 0.0, -1.0])
        assert dim == 4
        values = unpack_vector(blob)
        assert abs(math.sqrt(sum(v * v for v in values)) - 1.0) < 1e-6
        assert len(bits) == 1
        assert bits[0] & 0b10000000  # first component positive
        assert not bits[0] & 0b00010000  # fourth component negative

    def test_config(tmp: Path) -> None:
        paths = Paths(tmp / "cfg")
        paths.ensure()
        config = Config()
        config.set("sources.clipboard.enabled", True)
        config.set("chat_model", "test-model")
        config.save(paths)
        again = Config.load(paths)
        assert again.get("sources.clipboard.enabled") is True
        assert again.get("chat_model") == "test-model"
        assert again.enabled_sources() == ["clipboard"]
        assert again.validate() == []
        bad = Config({"ollama_url": "notaurl", "retention_days": 0})
        assert len(bad.validate()) >= 2

    def test_store_roundtrip(tmp: Path) -> None:
        store = Store(tmp / "store" / "a.db")
        fake = _FakeClient()
        rows = [
            {"ts": now_ts(), "source": "clipboard", "origin": "chrome",
             "text": "kubernetes audit logging config for the cluster",
             "vector": fake.embed_one("kubernetes audit logging config for the cluster")},
            {"ts": now_ts(), "source": "focus", "origin": "code",
             "text": "vscode: detection rules repo",
             "vector": fake.embed_one("vscode: detection rules repo")},
        ]
        assert store.insert_batch(rows) == 2
        assert store.count() == 2
        assert store.seen_recently(sha256_hex(rows[0]["text"]), "clipboard", 3600) is True
        assert store.seen_recently(sha256_hex("nothing"), "clipboard", 3600) is False
        keyword = store.keyword_search("kubernetes audit", limit=5)
        assert keyword and keyword[0][0] == 1, keyword
        stats = store.stats()
        assert stats["total"] == 2 and stats["pending"] == 0
        # retention
        store.conn.execute("UPDATE captures SET ts = ts - ? WHERE id = 2", (40 * 86400,))
        assert store.prune(30, 0) == 1
        assert store.count() == 1
        # keyword index must forget pruned rows
        assert all(row_id != 2 for row_id, _ in store.keyword_search("detection", limit=5))
        store.close()

    def test_pending_and_backfill(tmp: Path) -> None:
        store = Store(tmp / "store" / "b.db")
        store.insert_batch([{"ts": now_ts(), "source": "clipboard", "text": "no vector yet"}])
        assert store.count_pending() == 1
        pending = store.pending_embeddings()
        store.set_embeddings([(int(pending[0]["id"]), _FakeClient().embed_one("no vector yet"))])
        assert store.count_pending() == 0
        assert store.dominant_dim() == _FakeClient.DIM
        store.close()

    def test_vector_index(tmp: Path) -> None:
        store = Store(tmp / "store" / "c.db")
        fake = _FakeClient()
        texts = [
            "kubernetes cluster audit policy",
            "grocery list milk eggs bread",
            "detection engineering sigma rules",
            "flight booking to tokyo in march",
        ]
        store.insert_batch([{"ts": now_ts(), "source": "file", "text": t,
                             "vector": fake.embed_one(t)} for t in texts])
        index = VectorIndex()
        assert index.refresh(store) == 4
        query = fake.embed_one("kubernetes audit policy")
        results = index.search(query, top_k=2)
        assert results and results[0][0] == 1, results
        # incremental refresh
        store.insert_batch([{"ts": now_ts(), "source": "file", "text": "extra note",
                             "vector": fake.embed_one("extra note")}])
        assert index.refresh(store) == 1
        assert index.size() == 5
        # rebuild after deletion
        store.conn.execute("DELETE FROM captures WHERE id = 1")
        index.refresh(store)
        assert index.size() == 4
        assert all(row_id != 1 for row_id, _ in index.search(query, top_k=5))
        store.close()

    def test_vector_index_fallback(tmp: Path) -> None:
        """Exercise the no-numpy path explicitly."""
        global HAVE_NUMPY
        original = HAVE_NUMPY
        HAVE_NUMPY = False
        try:
            store = Store(tmp / "store" / "d.db")
            fake = _FakeClient()
            texts = ["alpha beta gamma", "delta epsilon zeta", "alpha beta delta"]
            store.insert_batch([{"ts": now_ts(), "source": "file", "text": t,
                                 "vector": fake.embed_one(t)} for t in texts])
            index = VectorIndex()
            index.refresh(store)
            results = index.search(fake.embed_one("alpha beta gamma"), top_k=3, candidates=10)
            assert results[0][0] == 1, results
            assert abs(results[0][1] - 1.0) < 1e-5, results
            store.close()
        finally:
            HAVE_NUMPY = original

    def test_retriever(tmp: Path) -> None:
        store = Store(tmp / "store" / "e.db")
        fake = _FakeClient()
        now = now_ts()
        entries = [
            (now - 86400, "kubernetes audit logging enabled on prod cluster"),
            (now - 20 * 86400, "kubernetes audit logging notes from last month"),
            (now - 3600, "lunch order pad thai"),
        ]
        store.insert_batch([{"ts": ts, "source": "clipboard", "text": text,
                             "vector": fake.embed_one(text)} for ts, text in entries])
        config = Config({"embed_model": "fake", "retrieval": {"top_k": 2}})
        retriever = Retriever(config, store, VectorIndex(), fake)  # type: ignore[arg-type]
        hits = retriever.retrieve("kubernetes audit logging")
        assert len(hits) == 2
        assert "kubernetes" in hits[0].text
        # recency weighting should prefer the newer of two equally relevant notes
        assert hits[0].ts > hits[1].ts
        context, used = retriever.build_context(hits)
        assert "[1]" in context and len(used) == 2
        narrow = retriever.retrieve("kubernetes audit logging", days=7)
        assert all(hit.ts >= now - 7 * 86400 for hit in narrow)
        store.close()

    def test_context_budget(tmp: Path) -> None:
        store = Store(tmp / "store" / "f.db")
        config = Config({"retrieval": {"context_chars": 200}})
        retriever = Retriever(config, store, VectorIndex(), _FakeClient())  # type: ignore[arg-type]
        hits = [Hit(id=i, ts=now_ts(), source="file", origin="", text="x" * 300, score=1.0)
                for i in range(5)]
        context, used = retriever.build_context(hits)
        assert len(used) == 1, len(used)
        assert len(context) < 600
        store.close()

    def test_ingest_worker(tmp: Path) -> None:
        paths = Paths(tmp / "ingest")
        paths.ensure()
        config = Config({"chat_model": "m", "embed_model": "e",
                         "runtime": {"embed_batch": 4, "batch_window_sec": 0.2}})
        fake = _FakeClient()
        ctx = DaemonContext(config, paths, fake, PlatformAdapter())  # type: ignore[arg-type]
        worker = IngestWorker(ctx)
        worker.start()
        ctx.submit(CaptureItem(source="clipboard", text="remember to rotate the vault token soon"))
        ctx.submit(CaptureItem(source="clipboard", text="AKIAIOSFODNN7EXAMPLE"))  # secret
        ctx.submit(CaptureItem(source="clipboard", text="remember to rotate the vault token soon"))
        time.sleep(1.2)
        ctx.stop_event.set()
        worker.join(timeout=10)
        store = Store(paths.db)
        assert store.count() == 1, store.count()
        assert ctx.stats.dropped_secret == 1
        assert ctx.stats.dropped_duplicate == 1
        row = store.recent(1)[0]
        assert row["embedding"] is not None
        store.close()

    def test_ingest_offline(tmp: Path) -> None:
        """Captures must survive Ollama being down, then backfill."""
        paths = Paths(tmp / "offline")
        paths.ensure()
        config = Config({"chat_model": "m", "embed_model": "e",
                         "runtime": {"embed_batch": 4, "batch_window_sec": 0.2}})
        fake = _FakeClient()
        fake.fail = True
        ctx = DaemonContext(config, paths, fake, PlatformAdapter())  # type: ignore[arg-type]
        worker = IngestWorker(ctx)
        worker.start()
        ctx.submit(CaptureItem(source="clipboard", text="offline capture should still persist"))
        time.sleep(0.8)
        ctx.stop_event.set()
        worker.join(timeout=10)

        store = Store(paths.db)
        assert store.count() == 1
        assert store.count_pending() == 1
        fake.fail = False
        pending = store.pending_embeddings()
        store.set_embeddings([(int(r["id"]), fake.embed_one(r["text"])) for r in pending])
        assert store.count_pending() == 0
        store.close()

    def test_focus_sessions(tmp: Path) -> None:
        paths = Paths(tmp / "focus")
        paths.ensure()
        config = Config({"sources": {"focus": {"enabled": True, "min_seconds": 0.1}}})
        ctx = DaemonContext(config, paths, _FakeClient(), PlatformAdapter())  # type: ignore[arg-type]

        class FakeAdapter(PlatformAdapter):
            def __init__(self) -> None:
                super().__init__()
                self.sequence = [Focus("code", "mind.py"), Focus("code", "mind.py"),
                                 Focus("chrome", "kubernetes docs"),
                                 Focus("1password", "vault")]
                self.position = 0

            def get_focus(self):
                focus = self.sequence[min(self.position, len(self.sequence) - 1)]
                self.position += 1
                return focus

        ctx.adapter = FakeAdapter()
        producer = FocusProducer(ctx)
        producer.tick()          # code/mind.py starts
        time.sleep(0.15)
        producer.tick()          # same window, no emit
        producer.tick()          # switches to chrome -> emits the code session
        time.sleep(0.15)
        producer.tick()          # switches to 1password -> emits chrome session
        time.sleep(0.15)
        producer.flush()         # 1password session must be suppressed

        items = []
        while not ctx.queue.empty():
            items.append(ctx.queue.get_nowait())
        texts = [item.text for item in items]
        assert any("code: mind.py" == t for t in texts), texts
        assert any("chrome: kubernetes docs" == t for t in texts), texts
        assert not any("1password" in t for t in texts), texts
        assert ctx.stats.dropped_denylist >= 1
        assert items[0].meta.get("duration_sec", 0) > 0

    def test_denylist(tmp: Path) -> None:
        paths = Paths(tmp / "deny")
        paths.ensure()
        ctx = DaemonContext(Config(), paths, _FakeClient(), PlatformAdapter())  # type: ignore[arg-type]
        assert ctx.is_denied(Focus("1Password", "vault")) is True
        assert ctx.is_denied(Focus("chrome", "Gmail — InPrivate")) is True
        assert ctx.is_denied(Focus("chrome", "kubernetes docs")) is False
        assert ctx.is_denied(None) is False

    def test_file_producer(tmp: Path) -> None:
        paths = Paths(tmp / "files")
        paths.ensure()
        watch = tmp / "notes"
        (watch / "sub").mkdir(parents=True)
        (watch / "a.md").write_text("first note about detection engineering", encoding="utf-8")
        (watch / "sub" / "b.md").write_text("second note about kubernetes", encoding="utf-8")
        (watch / "ignore.bin").write_text("binary-ish", encoding="utf-8")
        config = Config({"sources": {"files": {"enabled": True, "folders": [str(watch)],
                                               "scan_interval_sec": 3600}}})
        ctx = DaemonContext(config, paths, _FakeClient(), PlatformAdapter())  # type: ignore[arg-type]
        producer = FileProducer(ctx)
        producer.tick()
        first = []
        while not ctx.queue.empty():
            first.append(ctx.queue.get_nowait())
        assert len(first) == 2, [i.origin for i in first]
        assert {Path(i.origin).name for i in first} == {"a.md", "b.md"}

        producer.tick()  # unchanged -> nothing new
        assert ctx.queue.empty()

        (watch / "a.md").write_text("first note, now rewritten with new content",
                                    encoding="utf-8")
        os.utime(watch / "a.md", (time.time() + 1, time.time() + 1))
        producer.tick()
        second = []
        while not ctx.queue.empty():
            second.append(ctx.queue.get_nowait())
        assert len(second) == 1 and "rewritten" in second[0].text

        # deleting the file removes its chunks from the index
        store = Store(paths.db)
        store.insert_batch([{"ts": now_ts(), "source": "file", "origin": str(watch / "a.md"),
                             "text": "stale chunk"}])
        (watch / "a.md").unlink()
        producer.tick()
        remaining = [r["origin"] for r in store.recent(50, source="file")]
        assert str(watch / "a.md") not in remaining, remaining
        store.close()
        producer.store.close()

    def test_single_instance_lock(tmp: Path) -> None:
        paths = Paths(tmp / "lock")
        paths.ensure()
        first = SingleInstanceLock(paths.lock)
        assert first.acquire() is True
        second = SingleInstanceLock(paths.lock)
        assert second.acquire() is False
        first.release()
        third = SingleInstanceLock(paths.lock)
        assert third.acquire() is True
        third.release()

    def test_pause_flag(tmp: Path) -> None:
        paths = Paths(tmp / "pause")
        paths.ensure()
        ctx = DaemonContext(Config(), paths, _FakeClient(), PlatformAdapter())  # type: ignore[arg-type]
        assert ctx.is_paused() is False
        paths.paused.write_text("now", encoding="utf-8")
        assert ctx.is_paused() is True
        paths.paused.unlink()
        assert ctx.is_paused() is False

    def test_producer_lifecycle(tmp: Path) -> None:
        """Producers must start, capture, and join cleanly.

        Regression guard: naming an instance attribute `_stop` on a Thread
        subclass shadows threading.Thread._stop and makes join() raise.
        """
        paths = Paths(tmp / "lifecycle")
        paths.ensure()
        config = Config({"sources": {"clipboard": {"enabled": True, "poll_sec": 0.2,
                                                   "min_chars": 4}}})
        ctx = DaemonContext(config, paths, _FakeClient(), PlatformAdapter())  # type: ignore[arg-type]

        class FakeClipboard(PlatformAdapter):
            def get_clipboard(self) -> Optional[str]:
                return "a clipboard note worth keeping"

            def get_focus(self) -> Optional[Focus]:
                return Focus("editor", "notes")

        ctx.adapter = FakeClipboard()
        producer = ClipboardProducer(ctx)

        # The invariant is "no instance attribute shadows a Thread method",
        # checked directly rather than by asserting a private CPython name
        # exists — Thread._stop is an implementation detail that varies by
        # version, and asserting on it made this test fail on healthy code.
        shadowed = [name for name in vars(producer)
                    if callable(getattr(threading.Thread, name, None))]
        assert not shadowed, f"instance attributes shadow Thread methods: {shadowed}"

        producer.start()
        time.sleep(0.5)
        ctx.stop_event.set()
        producer.join(timeout=10)
        assert not producer.is_alive(), "producer thread failed to exit"
        assert ctx.queue.qsize() >= 1, "producer captured nothing"

    def test_macos_adapter(_tmp: Path) -> None:
        """MacAdapter parsing, permission probe, and backoff, with osascript mocked."""
        global _run
        original = _run
        canned = {"value": "Firefox\tGitHub — Mozilla Firefox\n"}

        def fake_run(cmd, timeout=3.0):
            return canned["value"]

        _run = fake_run
        try:
            adapter = MacAdapter()
            focus = adapter.get_focus()
            assert focus is not None and focus.app == "Firefox", focus
            assert focus.title == "GitHub — Mozilla Firefox", focus.title
            assert adapter.saw_title is True

            # An app with no titled window still yields the app name.
            canned["value"] = "Finder\t\n"
            focus = adapter.get_focus()
            assert focus is not None and focus.app == "Finder" and focus.title == ""

            # Accessibility denied is reported distinctly from "no window".
            canned["value"] = "ERR\t-1719\tSystem Events got an error"
            assert adapter.probe_focus_permission()[0] == "denied"
            canned["value"] = "ERR\t-1728\tno window"
            assert adapter.probe_focus_permission()[0] == "no-window"
            canned["value"] = "TITLE\tmind.py — Code"
            status, detail = adapter.probe_focus_permission()
            assert status == "ok" and "mind.py" in detail

            # After repeated failures it must stop spawning osascript.
            canned["value"] = None
            starved = MacAdapter()
            for _ in range(3):
                assert starved.get_focus() is None
            calls = {"n": 0}

            def counting_run(cmd, timeout=3.0):
                calls["n"] += 1
                return None

            _run = counting_run
            assert starved.get_focus() is None
            assert calls["n"] == 0, "backoff should suppress the spawn entirely"
        finally:
            _run = original

    def test_launch_plist(tmp: Path) -> None:
        """The generated LaunchAgent must parse as a real plist."""
        import plistlib

        paths = Paths(tmp / "plist")
        paths.ensure()
        raw = _launch_plist(paths, "/usr/bin/python3", "/Users/deer/mind.py", [])
        parsed = plistlib.loads(raw.encode("utf-8"))
        assert parsed["Label"] == LAUNCH_LABEL
        assert parsed["ProgramArguments"][0] == "/usr/bin/python3"
        assert parsed["ProgramArguments"][1] == "/Users/deer/mind.py"
        assert parsed["ProgramArguments"][-2:] == ["capture", "--quiet"]
        assert parsed["RunAtLoad"] is True and parsed["KeepAlive"] is True
        assert parsed["ProcessType"] == "Interactive"
        assert str(paths.home) in parsed["StandardErrorPath"]

    def test_folder_prompt_rejects_yes(tmp: Path) -> None:
        """The folders prompt follows two yes/no questions — 'y' must not
        become a watch folder called 'y'."""
        global prompt
        original = prompt
        real_dir = tmp / "notes"
        real_dir.mkdir(parents=True, exist_ok=True)
        answers = {"queue": ["y", str(real_dir)]}

        def scripted(_question: str, default: str = "") -> str:
            return answers["queue"].pop(0) if answers["queue"] else default

        prompt = scripted
        try:
            folders = _prompt_folders([], Console(io.StringIO()))
            assert folders == [str(real_dir)], folders

            answers["queue"] = ["y", "yes", "n"]
            assert _prompt_folders([], Console(io.StringIO())) == []

            answers["queue"] = ["/definitely/not/here", "", ""]
            assert _prompt_folders([], Console(io.StringIO())) == []
        finally:
            prompt = original

    def test_config_value_coercion(_tmp: Path) -> None:
        """Shells mangle JSON on the command line; the CLI must survive it."""
        key = "sources.files.folders"
        # PowerShell strips the inner double quotes from ["C:/x"] -> [C:/x]
        assert coerce_config_value(key, "[C:/Users/Halle/Documents]") == \
            ["C:/Users/Halle/Documents"]
        # bare path, no brackets at all
        assert coerce_config_value(key, "/home/me/notes") == ["/home/me/notes"]
        # comma separated, with stray quotes surviving from some other shell
        assert coerce_config_value(key, '[ "a" , \'b\' ]') == ["a", "b"]
        # a properly quoted list is passed through untouched
        assert coerce_config_value(key, ["x", "y"]) == ["x", "y"]
        # non-list keys are never coerced
        assert coerce_config_value("retention_days", 45) == 45
        assert coerce_config_value("chat_model", "qwen2.5:7b") == "qwen2.5:7b"
        # coercion also triggers when the existing value is a list
        assert coerce_config_value("custom.list", "a,b", existing=[]) == ["a", "b"]

    def test_maintenance_summary(tmp: Path) -> None:
        """A healthy daemon must log proof of life, not go silent for hours."""
        paths = Paths(tmp / "summary")
        paths.ensure()
        config = Config({"chat_model": "m", "embed_model": "e",
                         "runtime": {"summary_sec": 0.1}})
        ctx = DaemonContext(config, paths, _FakeClient(), PlatformAdapter())  # type: ignore[arg-type]
        worker = MaintenanceWorker(ctx)

        records: List[str] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = Capture()
        handler.setLevel(logging.DEBUG)
        previous_level = LOG.level
        LOG.addHandler(handler)
        LOG.setLevel(logging.INFO)
        try:
            ctx.stats.bump("captured", 3)
            ctx.stats.bump("stored", 2)
            worker._last_summary = 0.0
            worker._summary()
            assert any(line.startswith("alive:") for line in records), records
            assert any("2 stored" in line and "3 captured" in line for line in records), records

            # Silent-source warning after ten minutes with nothing captured
            records.clear()
            quiet = DaemonContext(config, paths, _FakeClient(), PlatformAdapter())  # type: ignore[arg-type]
            quiet.stats.started_at = now_ts() - 1200
            quiet_worker = MaintenanceWorker(quiet)
            quiet_worker._last_summary = 0.0
            quiet_worker._summary()
            assert any("no captures at all" in line for line in records), records
            quiet_worker.store.close()
        finally:
            LOG.removeHandler(handler)
            LOG.setLevel(previous_level)
            worker.store.close()

    def test_normalize_and_helpers(_tmp: Path) -> None:
        assert normalize_ws("  hello   world \x00 ") == "hello world"
        assert human_bytes(1536).endswith("KB")
        assert "ago" in human_age(now_ts() - 120)
        assert shannon_entropy("aaaa") == 0.0
        assert shannon_entropy("abcdefgh") > 2.5

    def test_reflect_schedule(tmp: Path) -> None:
        """The profile clock must survive restarts.

        It used to be set to now_ts() in __init__, so every daemon restart
        pushed the first reflection a full day into the future — a machine
        rebooted daily never built a profile at all.
        """
        paths = Paths(tmp / "reflect-home")
        paths.ensure()
        config = Config({"profile": {"enabled": True}})
        ctx = DaemonContext(config, paths, _FakeClient(), PlatformAdapter())

        worker = MaintenanceWorker(ctx)
        try:
            assert worker._last_reflect == 0.0, worker._last_reflect
            worker.store.set_meta("last_reflect_ts", "12345.0")
        finally:
            worker.store.close()

        restarted = MaintenanceWorker(ctx)
        try:
            assert restarted._last_reflect == 12345.0, restarted._last_reflect
        finally:
            restarted.store.close()

        # An unreachable model must NOT consume the interval: with Ollama down
        # the clock has to stay where it was so the next tick tries again.
        class _DownClient(_FakeClient):
            def is_up(self):
                return False

        down_ctx = DaemonContext(config, paths, _DownClient(), PlatformAdapter())
        down = MaintenanceWorker(down_ctx)
        try:
            down._last_reflect = 0.0
            down._reflect()
            assert down._last_reflect == 0.0, down._last_reflect
            assert not down.store.get_meta("last_reflect_ts_marked")
        finally:
            down.store.close()

        # A corrupt value must not crash the daemon on boot.
        again = MaintenanceWorker(ctx)
        again.store.set_meta("last_reflect_ts", "not-a-number")
        again.store.close()
        recovered = MaintenanceWorker(ctx)
        try:
            assert recovered._last_reflect == 0.0, recovered._last_reflect
        finally:
            recovered.store.close()

    def test_console_rendering(_tmp: Path) -> None:
        plain = Console(io.StringIO())
        plain.color = False

        # Glyphs must fall back cleanly on a console that cannot encode them.
        plain.unicode = True
        assert plain.g("ok") == "✓" and plain.g("rule") == "─"
        plain.unicode = False
        assert plain.g("ok") == "+" and plain.g("rule") == "-"
        assert all(ch.isascii() for ch in "".join(Console._ASCII_GLYPHS.values()))

        # kv() must align values into one column regardless of key length.
        buffer = io.StringIO()
        console = Console(buffer)
        console.color = False
        console.unicode = False
        console.kv("a", "1")
        console.kv("a much longer key", "2")
        console.kv("mid", "3")
        columns = [line.index(digit) for line, digit
                   in zip(buffer.getvalue().splitlines(), "123")]
        assert columns[0] == columns[2], columns   # short keys share a column
        assert columns[1] >= columns[0], columns   # an over-long key only pushes right

        # bar() clamps instead of drawing nonsense or raising.
        for fraction in (-5.0, 0.0, 0.5, 1.0, 42.0):
            bar = console.bar(fraction, 10)
            assert len(bar) == 10, (fraction, bar)
        assert console.bar(1.0, 10) == "#" * 10
        assert console.bar(0.0, 10) == "." * 10

        # With colour off nothing may emit an escape sequence.
        buffer2 = io.StringIO()
        quiet = Console(buffer2)
        quiet.color = False
        quiet.unicode = False
        quiet.title("mind", "doctor")
        quiet.section("setup")
        quiet.ok("fine")
        quiet.warn("hmm")
        quiet.fail("nope")
        quiet.sub("detail")
        assert "\033[" not in buffer2.getvalue(), buffer2.getvalue()

    def test_peers(tmp: Path) -> None:
        # Parsing has to survive every shape a node arrives in, including the
        # ones a shell mangles, and drop the rest without raising.
        cfg = Config({"peers": {"token": "SHARED", "nodes": [
            {"name": "laptop", "url": "http://laptop:7717"},
            "desktop=http://10.0.0.5:7717",
            {"name": "own", "url": "http://own:7717", "token": "OTHER"},
            "ftp://nope", "", 42,
        ]}})
        peers = {p.name: p for p in peer_nodes(cfg)}
        assert set(peers) == {"laptop", "desktop", "own"}, sorted(peers)
        assert peers["laptop"].token == "SHARED"
        assert peers["own"].token == "OTHER"
        mangled = Config({"peers": {"nodes": "[http://a:7717, http://b:7717]"}})
        assert len(peer_nodes(mangled)) == 2

        # A peer's hits must be distrusted on the way in and tagged on arrival.
        hit = Hit(id=1, ts=1.0, source="files", origin="a.md", text="x", score=0.5)
        assert hit_from_dict(hit_to_dict(hit), peer="box").peer == "box"
        assert "on box" in hit_from_dict(hit_to_dict(hit), peer="box").label()
        assert hit_from_dict({"id": 1}) is None
        assert hit_from_dict({"text": 7}) is None

        # The guard that matters: never listen off-loopback without a token.
        paths = Paths(tmp / "peer-home")
        unsafe = Config({"peers": {"serve_host": "0.0.0.0", "token": ""}})
        try:
            build_peer_server(unsafe, paths)
            raise AssertionError("bound a public address with no token")
        except MindError as exc:
            assert "token" in str(exc).lower(), str(exc)

        # A peer that is asleep must degrade to a local answer, not an error.
        store = Store(paths.db)
        try:
            store.insert_batch([{
                "ts": now_ts(), "source": "files", "origin": "a.md",
                "text": "vulkan descriptor indexing", "text_hash": "h1", "meta": "{}",
            }])
            offline = Config({
                "peers": {"enabled": True, "timeout_sec": 1,
                          "nodes": [{"name": "ghost", "url": "http://127.0.0.1:1"}]},
                "retrieval": {"top_k": 3},
            })
            fed = FederatedRetriever(offline, store, VectorIndex(), _FakeClient())
            hits = fed.retrieve("vulkan descriptor")
            assert hits, "a sleeping peer swallowed the local answer"
            assert all(not h.peer for h in hits), [h.peer for h in hits]
            assert fed.last_peers_answered == [], fed.last_peers_answered
        finally:
            store.close()

    return [
        ("chunking", test_chunking),
        ("redaction", test_redaction),
        ("peers", test_peers),
        ("console rendering", test_console_rendering),
        ("reflect schedule", test_reflect_schedule),
        ("vector packing", test_vector_pack),
        ("config", test_config),
        ("store roundtrip", test_store_roundtrip),
        ("pending/backfill", test_pending_and_backfill),
        ("vector index", test_vector_index),
        ("vector index (no numpy)", test_vector_index_fallback),
        ("retriever fusion", test_retriever),
        ("context budget", test_context_budget),
        ("ingest worker", test_ingest_worker),
        ("ingest offline", test_ingest_offline),
        ("focus sessions", test_focus_sessions),
        ("denylist", test_denylist),
        ("file producer", test_file_producer),
        ("single instance lock", test_single_instance_lock),
        ("pause flag", test_pause_flag),
        ("producer lifecycle", test_producer_lifecycle),
        ("macos adapter", test_macos_adapter),
        ("macos launch agent", test_launch_plist),
        ("folder prompt guards", test_folder_prompt_rejects_yes),
        ("config value coercion", test_config_value_coercion),
        ("maintenance summary", test_maintenance_summary),
        ("helpers", test_normalize_and_helpers),
    ]


def cmd_selftest(args: argparse.Namespace) -> int:
    import tempfile
    import traceback

    c = CONSOLE
    c.header(f"{APP_NAME} {VERSION} — selftest")
    passed = failed = 0
    with tempfile.TemporaryDirectory(prefix="mind-selftest-") as raw_tmp:
        tmp = Path(raw_tmp)
        for name, case in _selftest_cases():
            case_dir = tmp / re.sub(r"\W+", "_", name)
            case_dir.mkdir(parents=True, exist_ok=True)
            try:
                case(case_dir)
                c.ok(name)
                passed += 1
            except Exception as exc:
                c.fail(f"{name}: {exc}")
                if args.verbose:
                    c.write(CONSOLE.dim(traceback.format_exc()))
                failed += 1
    c.write("")
    if failed:
        c.write(c.red(f"{failed} failed, {passed} passed"))
        return 1
    c.write(c.green(f"all {passed} tests passed"))
    return 0


# ==========================================================================
# Entry point
# ==========================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Local-only personal memory assistant (Ollama-backed).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Run `{APP_NAME} setup` first, then `{APP_NAME} install` and `{APP_NAME} chat`.",
    )
    parser.add_argument("--home", help="data directory (default: ~/.mind or $MIND_HOME)")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("setup", help="interactive configuration wizard").set_defaults(func=cmd_setup)
    sub.add_parser("doctor", help="check the whole setup and suggest fixes").set_defaults(func=cmd_doctor)

    p_capture = sub.add_parser("capture", help="run the capture daemon in the foreground")
    p_capture.add_argument("--quiet", action="store_true", help="log to file only")
    p_capture.set_defaults(func=cmd_capture)

    p_chat = sub.add_parser("chat", help="interactive chat grounded in your captured memory")
    p_chat.add_argument("--model", help="override the chat model")
    p_chat.add_argument("--days", type=int, help="memory window in days")
    p_chat.add_argument("--no-memory", action="store_true", help="disable retrieval")
    p_chat.add_argument("--resume", action="store_true", help="continue the previous conversation")
    p_chat.add_argument("--no-agent", action="store_true",
                        help="disable auto-research and tools; plain retrieval only")
    p_chat.add_argument("--no-sources", dest="show_sources", action="store_false",
                        help="don't print the source list after answers")
    p_chat.add_argument("--local", action="store_true", help="answer from this machine only; don't ask peers")
    p_chat.set_defaults(func=cmd_chat, show_sources=True)

    p_ask = sub.add_parser("ask", help="one-shot question (good for scripts)")
    p_ask.add_argument("question", nargs="+")
    p_ask.add_argument("--model")
    p_ask.add_argument("--days", type=int)
    p_ask.add_argument("--no-memory", action="store_true")
    p_ask.add_argument("--no-agent", action="store_true",
                       help="skip web research/tools; answer from memory only")
    p_ask.add_argument("--no-stream", action="store_true")
    p_ask.add_argument("--trace", action="store_true",
                       help="show research and tool calls the agent made")
    p_ask.add_argument("--show-prompt", action="store_true",
                       help="print the full prompt sent to the model (retrieval mode)")
    p_ask.add_argument("--sources", dest="show_sources", action="store_true",
                       help="print the sources used")
    p_ask.add_argument("--local", action="store_true", help="answer from this machine only; don't ask peers")
    p_ask.set_defaults(func=cmd_ask, show_sources=False)

    p_search = sub.add_parser("search", help="search memory without invoking the chat model")
    p_search.add_argument("query", nargs="+")
    p_search.add_argument("--days", type=int)
    p_search.add_argument("--limit", type=int, default=10)
    p_search.add_argument("--json", action="store_true")
    p_search.add_argument("--local", action="store_true", help="answer from this machine only; don't ask peers")
    p_search.set_defaults(func=cmd_search)

    p_status = sub.add_parser("status", help="show configuration, daemon state, and stats")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_forget = sub.add_parser("forget", help="delete captured data")
    p_forget.add_argument("--all", action="store_true")
    p_forget.add_argument("--older-than", type=int, metavar="DAYS")
    p_forget.add_argument("--source", help="clipboard | focus | file")
    p_forget.add_argument("--matching", help="delete entries containing this text")
    p_forget.add_argument("--yes", action="store_true", help="skip confirmation")
    p_forget.set_defaults(func=cmd_forget)

    p_export = sub.add_parser("export", help="export captures as JSONL")
    p_export.add_argument("--out", help="output file (default: stdout)")
    p_export.add_argument("--days", type=int, help="only the last N days")
    p_export.set_defaults(func=cmd_export)

    p_reindex = sub.add_parser("reindex", help="re-embed captures with the current model")
    p_reindex.add_argument("--all", action="store_true", help="re-embed everything, not just pending")
    p_reindex.set_defaults(func=cmd_reindex)

    p_agent = sub.add_parser("agent", help="ask a question the assistant can research with tools")
    p_agent.add_argument("question", nargs="+")
    p_agent.add_argument("--model")
    p_agent.add_argument("--no-trace", dest="trace", action="store_false",
                         help="hide the tool calls it makes")
    p_agent.add_argument("--local", action="store_true", help="answer from this machine only; don't ask peers")
    p_agent.set_defaults(func=cmd_agent, trace=True)

    p_tool = sub.add_parser("tool", help="call one agent tool directly (no model involved)")
    p_tool.add_argument("name", help="resolve_time | timeline | search_memory | fetch_url | "
                                     "wikipedia | web_search")
    p_tool.add_argument("arguments", nargs="*", metavar="KEY=VALUE")
    p_tool.set_defaults(func=cmd_tool)

    p_net = sub.add_parser("netcheck", help="verify internet access layer by layer")
    p_net.add_argument("--topic", default="Detection engineering",
                       help="subject to look up during the live checks")
    p_net.add_argument("--video", help="a YouTube URL to test transcript extraction")
    p_net.add_argument("--verbose", action="store_true", help="show fetched content and the audit log")
    p_net.set_defaults(func=cmd_netcheck)

    p_enc = sub.add_parser("encrypt", help="encrypt the database at rest (or check status)")
    p_enc.add_argument("action", nargs="?", choices=["status", "on", "off"], default="status",
                       help="status (default), on, or off")
    p_enc.add_argument("--provider", choices=sorted(PROVIDER_CLASSES),
                       help="where to keep the key (default: best for this OS)")
    p_enc.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p_enc.set_defaults(func=cmd_encrypt)

    p_serve = sub.add_parser("serve",
                             help="answer queries from other machines you own (read-only)")
    p_serve.add_argument("--host", help="bind address (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, help="port (default: 7717)")
    p_serve.add_argument("--verbose", action="store_true", help="log to the console")
    p_serve.set_defaults(func=cmd_serve)

    p_peer = sub.add_parser("peer", help="the other machines this one can ask")
    p_peer.add_argument("action", nargs="?", default="list",
                        choices=["list", "add", "remove", "ping", "token"])
    p_peer.add_argument("name", nargs="?", help="peer name (add/remove)")
    p_peer.add_argument("url", nargs="?", help="peer address, e.g. http://laptop:7717")
    p_peer.add_argument("--token", help="token for this peer only")
    p_peer.add_argument("--new", action="store_true", help="generate a mesh token")
    p_peer.set_defaults(func=cmd_peer)

    p_ws = sub.add_parser("websearch",
                          help="debug the web search backends engine by engine")
    p_ws.add_argument("query", help="the search query to run against every engine")
    p_ws.add_argument("--save", action="store_true",
                      help="save each engine's raw HTML next to the config for sharing")
    p_ws.set_defaults(func=cmd_websearch)

    p_prof = sub.add_parser("profile", help="what it has learned about you (durable memory)")
    p_prof.add_argument("--reflect", action="store_true", help="run a consolidation pass now")
    p_prof.add_argument("--force", action="store_true", help="reflect even with little new data")
    p_prof.add_argument("--add", nargs="+", metavar="FACT", help="add a fact by hand")
    p_prof.add_argument("--category", help="category for --add")
    p_prof.add_argument("--forget", nargs="?", const="", metavar="TEXT",
                        help="forget facts matching text, or all with no text")
    p_prof.add_argument("--why", action="store_true", help="show age and confidence per fact")
    p_prof.add_argument("--json", action="store_true")
    p_prof.set_defaults(func=cmd_profile)

    p_screen = sub.add_parser("screentime", help="time spent per app/game from focus capture")
    p_screen.add_argument("expr", nargs="*", help="a time expression, e.g. 'yesterday' or 'today'")
    p_screen.add_argument("--days", type=int, default=1, help="window if no expression given")
    p_screen.add_argument("--limit", type=int, default=20)
    p_screen.set_defaults(func=cmd_screentime)

    p_know = sub.add_parser("knowledge", help="inspect the cache of researched answers")
    p_know.add_argument("--all", action="store_true", help="include expired entries")
    p_know.add_argument("--verbose", action="store_true", help="show a preview of each answer")
    p_know.add_argument("--forget", nargs="?", const="", metavar="TEXT",
                        help="forget matching entries, or all of them if no text given")
    p_know.add_argument("--prune", action="store_true", help="delete expired entries now")
    p_know.set_defaults(func=cmd_knowledge)

    p_watch = sub.add_parser("watch", help="list, add, or remove indexed folders")
    p_watch.add_argument("paths", nargs="*", help="folders to index")
    p_watch.add_argument("--remove", nargs="+", metavar="PATH", help="stop indexing these folders")
    p_watch.add_argument("--clear", action="store_true", help="remove every watch folder")
    p_watch.set_defaults(func=cmd_watch)

    sub.add_parser("pause", help="stop capturing without uninstalling").set_defaults(func=cmd_pause)
    sub.add_parser("resume", help="resume capturing").set_defaults(func=cmd_resume)
    sub.add_parser("install", help="run capture automatically at login").set_defaults(func=cmd_install)
    sub.add_parser("uninstall", help="remove the autostart entry").set_defaults(func=cmd_uninstall)

    p_config = sub.add_parser("config", help="show or change configuration")
    p_config.add_argument("--set", action="append", metavar="KEY=VALUE",
                          help="e.g. --set retention_days=60 --set sources.focus.enabled=true")
    p_config.add_argument("--get", metavar="KEY")
    p_config.add_argument("--path", action="store_true", help="print the config file path")
    p_config.set_defaults(func=cmd_config)

    p_selftest = sub.add_parser("selftest", help="run the built-in test suite")
    p_selftest.add_argument("--verbose", action="store_true")
    p_selftest.set_defaults(func=cmd_selftest)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except MindError as exc:
        CONSOLE.write(CONSOLE.red(f"error: {exc}"))
        return 1
    except KeyboardInterrupt:
        CONSOLE.write("")
        return 130


if __name__ == "__main__":
    sys.exit(main())