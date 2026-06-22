#!/usr/bin/env python3
"""
SMB share enumerator using Impacket.
Reads targets from a socks.txt-style file, connects with null session (or overrides),
lists shares, verifies accessibility, dedupes by (IP, share-set), and prints results.
Uses multi-threading for speed. Optional: run under proxychains for SOCKS.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

# Impacket
from impacket.smbconnection import SMBConnection, SessionError

try:
    from impacket.nmb import NetBIOSError
except ImportError:
    NetBIOSError = None  # type: ignore[misc, assignment]

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    Fore = Style = None  # type: ignore[misc, assignment]
    def colorama_init(*args, **kwargs): pass

# Debug: set by run() when --debug; use _debug_lock for stderr
DEBUG = False
_debug_lock = Lock()

# -----------------------------------------------------------------------------
# Colors (colorama; safe when not TTY)
# -----------------------------------------------------------------------------
def _colorama_ready() -> None:
    try:
        is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        colorama_init(strip=not is_tty)
    except Exception:
        pass


def _c(style: str, text: str) -> str:
    """Apply colorama style to text; no-op if colorama unavailable."""
    if Fore is None or Style is None:
        return text
    return style + text + Style.RESET_ALL

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
DEFAULT_INFILE = "socks.txt"
EXCLUDE_SHARES_RE = re.compile(r"^(C\$|ADMIN\$|IPC\$)$", re.IGNORECASE)
SMB_PORT = 445
CONNECT_TIMEOUT = 15

# Optional env overrides (same as bash: SMB_DOMAIN, SMB_USER)
SMB_DOMAIN_OVERRIDE = os.environ.get("SMB_DOMAIN", "").strip()
SMB_USER_OVERRIDE = os.environ.get("SMB_USER", "").strip()


# -----------------------------------------------------------------------------
# Input parsing
# -----------------------------------------------------------------------------
def parse_socks_file(path: Path) -> list[tuple[str, str, str]]:
    """Parse socks.txt: lines with SMB, IP, and DOMAIN/USER. Returns (ip, domain, user)."""
    targets: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3 or parts[0].upper() != "SMB":
                continue
            ip = parts[1].strip()
            domuser = parts[2].strip()
            if "/" in domuser:
                domain, _, user = domuser.partition("/")
                domain, user = domain.strip(), user.strip()
            else:
                domain, user = "", domuser

            if SMB_DOMAIN_OVERRIDE:
                domain = SMB_DOMAIN_OVERRIDE
            if SMB_USER_OVERRIDE:
                user = SMB_USER_OVERRIDE

            key = (ip, domain, user)
            if key not in seen:
                seen.add(key)
                targets.append(key)

    return targets


def get_targets_single_user(path: Path) -> list[tuple[str, str, str]]:
    """One credential for all unique IPs (SMB_USER set). Domain from SMB_DOMAIN or empty."""
    ips: set[str] = set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[0].upper() == "SMB":
                ips.add(parts[1].strip())
    domain = SMB_DOMAIN_OVERRIDE or ""
    user = SMB_USER_OVERRIDE
    return [(ip, domain, user) for ip in sorted(ips)]


# -----------------------------------------------------------------------------
# SMB logic
# -----------------------------------------------------------------------------
def _normalize_share_name(s: str) -> str:
    """Remove trailing null bytes and strip whitespace (SMB share names must not include nulls)."""
    if not s:
        return s
    return s.rstrip("\x00").strip()


def _ndr_string(val) -> str | None:
    """Get string from NDR LPWSTR (pointer or inline). Returns None if not a string."""
    if val is None:
        return None
    if isinstance(val, str):
        return _normalize_share_name(val) or None
    if isinstance(val, bytes):
        return _normalize_share_name(val.decode("utf-16-le", errors="replace")) or None
    # NDR LPWSTR: referent is (Data, WSTR). Dereference via ['Data'] then get bytes from inner.
    try:
        if hasattr(val, "__getitem__"):
            data = val["Data"]
            if data is not None:
                if isinstance(data, bytes):
                    return _normalize_share_name(data.decode("utf-16-le", errors="replace")) or None
                if hasattr(data, "getData"):
                    raw = data.getData()
                    if isinstance(raw, bytes):
                        return _normalize_share_name(raw.decode("utf-16-le", errors="replace")) or None
                out = _ndr_string(data)
                if out:
                    return out
    except (KeyError, TypeError, IndexError):
        pass
    if hasattr(val, "getData"):
        data = val.getData()
        if isinstance(data, bytes):
            return _normalize_share_name(data.decode("utf-16-le", errors="replace")) or None
        out = _ndr_string(data)
        if out:
            return out
    if hasattr(val, "valueOf"):
        return _ndr_string(val.valueOf())
    try:
        if hasattr(val, "fields"):
            fields = getattr(val, "fields", None)
            if isinstance(fields, dict):
                data = fields.get("Data")
                if data is not None:
                    if isinstance(data, bytes):
                        return _normalize_share_name(data.decode("utf-16-le", errors="replace")) or None
                    if hasattr(data, "getData"):
                        raw = data.getData()
                        if isinstance(raw, bytes):
                            return _normalize_share_name(raw.decode("utf-16-le", errors="replace")) or None
                    out = _ndr_string(data)
                    if out:
                        return out
    except Exception:
        pass
    s = _normalize_share_name(str(val))
    return s if s and not s.startswith("<") else None


def _get_field(obj, key: str):
    """Get attribute or key from NDR struct or dict. NDR uses .fields or __getitem__."""
    if obj is None:
        return None
    try:
        if isinstance(obj, dict):
            return obj.get(key)
        # NDR struct: field may be in .fields (e.g. entry.fields['shi1_netname'])
        if hasattr(obj, "fields") and isinstance(getattr(obj, "fields", None), dict) and key in obj.fields:
            return obj.fields[key]
        # __getitem__ returns referent Data for pointers
        if hasattr(obj, "__getitem__"):
            try:
                return obj[key]
            except (KeyError, TypeError, IndexError):
                pass
        return getattr(obj, key, None)
    except (KeyError, TypeError):
        return None


def _share_entry_struct(entry) -> list:
    """Get the SHARE_INFO_1 struct from an entry (may be SHARE_INFO_1 or LPSHARE_INFO_1)."""
    candidates = [entry]
    data = _get_field(entry, "Data")
    if data is not None:
        candidates.append(data)
    return candidates


def get_share_name(entry) -> str:
    """Extract share name from listShares() Level1 entry (NDR struct; may be pointer to SHARE_INFO_1)."""
    for base in _share_entry_struct(entry):
        if base is None:
            continue
        raw = _get_field(base, "shi1_netname")
        if raw is not None:
            name = _ndr_string(raw)
            if name:
                return _normalize_share_name(name)
    for base in _share_entry_struct(entry):
        if base is None:
            continue
        raw = _get_field(base, "shi1_remark")
        if raw is not None:
            name = _ndr_string(raw)
            if name:
                return _normalize_share_name(name)
    return ""


def _debug(msg: str) -> None:
    if DEBUG:
        with _debug_lock:
            print(f"[DEBUG] {msg}", file=sys.stderr, flush=True)


def list_shares(conn: SMBConnection) -> list[str]:
    """List share names, excluding C$, ADMIN$, IPC$."""
    raw = conn.listShares()
    names = []
    for i, entry in enumerate(raw):
        name = get_share_name(entry)
        if name and not EXCLUDE_SHARES_RE.match(name):
            names.append(name)
        elif DEBUG and i == 0 and raw:
            # Debug: show first entry structure when we have raw but no names
            try:
                e0 = raw[0]
                info = f"type={type(e0).__name__}"
                if hasattr(e0, "shi1_netname"):
                    nn = getattr(e0, "shi1_netname")
                    info += f" shi1_netname type={type(nn).__name__}"
                    if hasattr(nn, "getData"):
                        info += f" getData()={nn.getData()!r}"
                    if hasattr(nn, "getDataLen"):
                        info += f" getDataLen"
                    if hasattr(nn, "fields"):
                        info += f" fields={getattr(nn, 'fields', None)}"
                if hasattr(e0, "keys"):
                    info += f" keys={list(e0.keys())}"
                if hasattr(e0, "fields"):
                    info += f" entry.fields={getattr(e0, 'fields', None)}"
                _debug(f"list_shares: first entry: {info}")
            except Exception as ex:
                _debug(f"list_shares: first entry debug: {ex}")
    result = sorted(set(names))
    _debug(f"list_shares: raw_count={len(raw)} -> after exclude: {result}")
    return result


def is_share_accessible(conn: SMBConnection, share_name: str) -> bool:
    """Test access by listing root of share. Returns True if listPath succeeds."""
    share_name = _normalize_share_name(share_name)
    if not share_name:
        return False
    for path in ("", "*"):
        try:
            conn.listPath(share_name, path)
            _debug(f"  listPath({share_name!r}, {path!r}) -> OK")
            return True
        except SessionError as e:
            _debug(f"  listPath({share_name!r}, {path!r}) -> {e}")
            continue
    _debug(f"  share {share_name!r}: no path worked")
    return False


def get_accessible_shares(conn: SMBConnection, share_names: list[str]) -> list[str]:
    """Filter to shares we can actually list (root dir)."""
    _debug(f"get_accessible_shares: testing {len(share_names)} shares: {share_names[:10]}{'...' if len(share_names) > 10 else ''}")
    accessible = []
    for name in share_names:
        if is_share_accessible(conn, name):
            accessible.append(name)
    result = sorted(accessible)
    _debug(f"get_accessible_shares: -> {len(result)} accessible: {result}")
    return result


def process_one(ip: str, domain: str, user: str) -> tuple[str, str, str, list[str]] | None:
    """Connect, list shares, test access. Returns (ip, domain, user, accessible_shares) or None on failure."""
    conn = None
    try:
        _debug(f"{ip} ({domain}/{user}): connecting...")
        conn = SMBConnection(
            remoteName=ip,
            remoteHost=ip,
            sess_port=SMB_PORT,
            timeout=CONNECT_TIMEOUT,
        )
        _debug(f"{ip}: login({user!r}, '', {domain!r})...")
        conn.login(user, "", domain)
        shares = list_shares(conn)
        _debug(f"{ip}: listed {len(shares)} shares, checking access...")
        accessible = get_accessible_shares(conn, shares)
        _debug(f"{ip}: done. accessible={len(accessible)} -> {accessible}")
        return (ip, domain, user, accessible)
    except Exception as e:
        _debug(f"{ip} ({domain}/{user}): FAILED: {e}")
        # Skip traceback for expected network/auth failures (NetBIOSError, SessionError)
        expected = (SessionError,) + ((NetBIOSError,) if NetBIOSError is not None else ())
        if DEBUG and isinstance(e, expected):
            pass
        elif DEBUG:
            with _debug_lock:
                traceback.print_exc(file=sys.stderr)
        return None
    finally:
        if conn is not None:
            try:
                conn.logoff()
            except Exception:
                pass
            try:
                conn.close()
            except Exception as e:
                _debug(f"{ip}: close() failed (ignored): {e}")


# -----------------------------------------------------------------------------
# Dedupe and output
# -----------------------------------------------------------------------------
def dedupe_key(ip: str, shares: list[str]) -> tuple[str, tuple[str, ...]]:
    """Fingerprint for per-IP dedupe: same (ip, frozenset of shares) = duplicate."""
    return (ip, tuple(sorted(shares)))


def _print_banner(target_count: int, workers: int) -> None:
    """Print a simple banner at startup."""
    _colorama_ready()
    if Fore and Style:
        title = _c(Fore.CYAN + Style.BRIGHT, "SMBTHIEF")
        sub = _c(Fore.CYAN + Style.DIM, " — SMB share enumerator (Impacket)")
        print()
        print(f"  {title}{sub}")
    else:
        print()
        print("  SMBTHIEF — SMB share enumerator (Impacket)")
    print(f"  Targets: {target_count}  ·  Workers: {workers}")
    print()
    sys.stdout.flush()


def run(
    infile: Path,
    workers: int,
    verbose: bool,
    debug: bool = False,
) -> None:
    global DEBUG
    DEBUG = debug
    _colorama_ready()
    if DEBUG:
        with _debug_lock:
            print(_c(Style.DIM, "[DEBUG] verbose debugging enabled"), file=sys.stderr, flush=True)

    if SMB_USER_OVERRIDE:
        targets = get_targets_single_user(infile)
    else:
        targets = parse_socks_file(infile)

    if not targets:
        err = _c(Fore.RED + Style.BRIGHT, "No targets found.") if Fore else "No targets found."
        print(err, file=sys.stderr)
        return

    _print_banner(len(targets), workers)

    seen: set[tuple[str, tuple[str, ...]]] = set()
    print_lock = Lock()

    def maybe_emit(ip: str, domain: str, user: str, accessible: list[str]) -> bool:
        if not accessible:
            _debug(f"maybe_emit {ip}: skip (no accessible shares)")
            return False
        key = dedupe_key(ip, accessible)
        with print_lock:
            if key in seen:
                _debug(f"maybe_emit {ip}: skip (duplicate key)")
                return False
            seen.add(key)
        _debug(f"maybe_emit {ip}: EMIT ({len(accessible)} shares)")

        # Simple lines: header + list with [*] and hyphens
        with print_lock:
            header = f"{ip}  ({domain}/{user})"
            if Fore:
                header = _c(Fore.CYAN + Style.BRIGHT, header)
            print()
            print(f"  {header}")
            print("  " + "-" * 50)
            for s in accessible:
                bullet = _c(Fore.GREEN, "[*]") if Fore else "[*]"
                name = _c(Fore.GREEN, s) if Fore else s
                print(f"  {bullet} {name}")
            print()
        return True

    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(process_one, ip, domain, user): (ip, domain, user)
            for ip, domain, user in targets
        }
        for fut in as_completed(futures):
            ip, domain, user = futures[fut]
            if verbose:
                with print_lock:
                    completed += 1
                    if Fore:
                        prog = _c(Style.DIM, f"[{completed}/{len(targets)}]") + " " + _c(Fore.CYAN, ip) + _c(Style.DIM, f" ({domain}/{user})")
                    else:
                        prog = f"[{completed}/{len(targets)}] {ip} ({domain}/{user})"
                    print(prog, file=sys.stderr)
            try:
                result = fut.result()
                if result:
                    _ip, _domain, _user, accessible = result
                    maybe_emit(_ip, _domain, _user, accessible)
            except Exception as e:
                if verbose:
                    with print_lock:
                        err = _c(Fore.RED + Style.BRIGHT, f"  Error: {e}") if Fore else f"  Error: {e}"
                        print(err, file=sys.stderr)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enumerate accessible SMB shares from a socks.txt-style target list (Impacket)."
    )
    parser.add_argument(
        "infile",
        nargs="?",
        default=DEFAULT_INFILE,
        type=Path,
        help=f"Input file (default: {DEFAULT_INFILE})",
    )
    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=min(32, (os.cpu_count() or 4) * 4),
        help="Max concurrent workers (default: min(32, 4*cpu))",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print progress per target to stderr",
    )
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Verbose debug: connect/login/share/listPath/emit per target (stderr)",
    )
    args = parser.parse_args()
    _colorama_ready()

    if not args.infile.exists():
        err = _c(Fore.RED + Style.BRIGHT, f"File not found: {args.infile}") if Fore else f"File not found: {args.infile}"
        print(err, file=sys.stderr)
        return 1

    run(args.infile, workers=args.jobs, verbose=args.verbose, debug=args.debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
