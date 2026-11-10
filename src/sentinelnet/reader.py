"""Incremental, rotation-safe line reader for append-only JSON log files.

Guarantees:
* A line is only emitted once its terminating newline has been seen, so a
  half-written record is never parsed (it is held until completed).
* Rotation (inode change) and truncation (size < offset) reset the offset.
* Memory is bounded: at most ``max_read_bytes`` are read per call and a line
  longer than ``max_line_bytes`` is flagged ``oversize`` instead of buffered.
* With ``final=True`` (offline files that will not grow) an unterminated last
  line is emitted flagged ``complete=False`` so it is reported as truncated.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_LINE_BYTES = 64 * 1024
DEFAULT_MAX_READ_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class RawLine:
    offset: int
    data: bytes
    complete: bool = True
    oversize: bool = False


class IncrementalReader:
    def __init__(
        self,
        path: Path,
        *,
        max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
        max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    ) -> None:
        self.path = path
        self.max_line_bytes = max_line_bytes
        self.max_read_bytes = max_read_bytes
        self.offset = 0
        self._inode: int | None = None
        self.rotations = 0

    def read_new(self, *, final: bool = False) -> Iterator[RawLine]:
        st = os.stat(self.path)
        if self._inode is not None and (st.st_ino != self._inode or st.st_size < self.offset):
            self.offset = 0
            self.rotations += 1
        self._inode = st.st_ino

        with open(self.path, "rb") as fh:  # noqa: PTH123
            fh.seek(self.offset)
            chunk = fh.read(self.max_read_bytes)

        pos = 0
        while pos < len(chunk):
            nl = chunk.find(b"\n", pos)
            if nl == -1:
                tail = chunk[pos:]
                if len(tail) > self.max_line_bytes:
                    yield RawLine(self.offset + pos, b"", complete=False, oversize=True)
                    self.offset += len(chunk)
                elif final and len(chunk) < self.max_read_bytes:
                    yield RawLine(self.offset + pos, tail, complete=False)
                    self.offset += len(chunk)
                else:
                    self.offset += pos  # hold the partial line for the next call
                return
            line = chunk[pos:nl]
            if line.endswith(b"\r"):
                line = line[:-1]
            if len(line) > self.max_line_bytes:
                yield RawLine(self.offset + pos, b"", oversize=True)
            else:
                yield RawLine(self.offset + pos, line)
            pos = nl + 1
        self.offset += len(chunk)
