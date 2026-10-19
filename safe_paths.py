"""Contained file access for CLI-controlled inputs and outputs."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PureWindowsPath
from typing import Literal


class PathSecurityError(OSError):
    """Raised when a CLI file path escapes its permitted boundary."""


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve(
    path: str | os.PathLike[str],
    root: Path,
    *,
    writing: bool,
    allow_external: bool,
) -> tuple[Path, Path]:
    raw = os.fspath(path)
    if "\x00" in raw:
        raise PathSecurityError("NUL byte in file path")
    windows_path = PureWindowsPath(raw)
    if windows_path.drive and os.name != "nt":
        raise PathSecurityError("Windows drive paths are not valid on this platform")

    root = root.resolve(strict=True)
    requested = Path(raw)
    candidate = requested if requested.is_absolute() else root / requested
    if not allow_external and not _under(Path(os.path.abspath(candidate)), root):
        raise PathSecurityError("file path is outside the workspace")
    try:
        if writing:
            if candidate.name in ("", ".", ".."):
                raise PathSecurityError("output path must name a file")
            parent = candidate.parent.resolve(strict=True)
            resolved = parent / candidate.name
            if candidate.is_symlink():
                raise PathSecurityError("output path cannot be a symbolic link")
        else:
            resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        if isinstance(exc, PathSecurityError):
            raise
        if isinstance(exc, FileNotFoundError):
            raise
        raise PathSecurityError("file path cannot be resolved") from exc

    if not allow_external and not _under(resolved, root):
        raise PathSecurityError("file path is outside the workspace")
    return resolved, root


def _open_posix(path: Path, root: Path, mode: Literal["r", "w", "a"], allow_external: bool) -> int:
    boundary = Path(path.anchor) if allow_external else root
    relative = path.relative_to(boundary)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(boundary, flags)
    try:
        parts = relative.parts
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                flags,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd

        if not parts:
            raise PathSecurityError("file path must name a regular file")
        file_flags = {
            "r": os.O_RDONLY,
            "w": os.O_WRONLY | os.O_CREAT,
            "a": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
        }[mode]
        file_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        file_fd = os.open(parts[-1], file_flags, 0o600, dir_fd=directory_fd)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            os.close(file_fd)
            raise PathSecurityError("file path must refer to a regular file")
        if mode == "w":
            os.ftruncate(file_fd, 0)
        return file_fd
    finally:
        os.close(directory_fd)


def _windows_handle_path(file_fd: int) -> Path:
    import ctypes
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
    get_final_path.restype = ctypes.c_uint32
    handle = msvcrt.get_osfhandle(file_fd)
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_final_path(handle, buffer, len(buffer), 0)
    if not length or length >= len(buffer):
        raise PathSecurityError("unable to verify opened file path")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value).resolve(strict=True)


def _open_windows(
    path: Path,
    root: Path,
    mode: Literal["r", "w", "a"],
    allow_external: bool,
) -> int:
    parts = list(path.parents)
    parts.reverse()
    for parent in parts:
        try:
            info = parent.lstat()
        except OSError as exc:
            raise PathSecurityError("file path parent cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
        ):
            raise PathSecurityError("file path cannot traverse a reparse point")

    flags = {"r": os.O_RDONLY, "w": os.O_WRONLY | os.O_CREAT, "a": os.O_WRONLY | os.O_CREAT | os.O_APPEND}[mode]
    flags |= getattr(os, "O_BINARY", 0)
    file_fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise PathSecurityError("file path must refer to a regular file")
        actual = _windows_handle_path(file_fd)
        if not allow_external and not _under(actual, root):
            raise PathSecurityError("opened file is outside the workspace")
        if mode == "w":
            os.ftruncate(file_fd, 0)
        return file_fd
    except Exception:
        os.close(file_fd)
        raise


def open_path(
    path: str | os.PathLike[str],
    workspace_root: Path,
    mode: Literal["r", "w", "a"] = "r",
    *,
    allow_external: bool = False,
):
    """Open a regular file after containment checks and no-follow traversal."""
    resolved, root = _resolve(
        path,
        workspace_root,
        writing=mode != "r",
        allow_external=allow_external,
    )
    if os.name == "nt":
        file_fd = _open_windows(resolved, root, mode, allow_external)
    else:
        file_fd = _open_posix(resolved, root, mode, allow_external)
    return os.fdopen(file_fd, {"r": "rb", "w": "wb", "a": "ab"}[mode])


def read_text(
    path: str | os.PathLike[str],
    workspace_root: Path,
    *,
    allow_external: bool = False,
) -> str:
    with open_path(path, workspace_root, allow_external=allow_external) as source:
        return source.read().decode("utf-8")


def write_text(
    path: str | os.PathLike[str],
    text: str,
    workspace_root: Path,
    *,
    append: bool = False,
    allow_external: bool = False,
) -> None:
    mode: Literal["w", "a"] = "a" if append else "w"
    with open_path(path, workspace_root, mode, allow_external=allow_external) as destination:
        destination.write(text.encode("utf-8"))
