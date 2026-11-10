"""One-click fixes for what the Wi-Fi & exposure scan finds (Windows).

Each fix is a short PowerShell command built only from validated values (an
interface number, a profile name, a port number, or a service name from the
list below), never from text taken off the network. It runs elevated: Windows
shows its own administrator (UAC) prompt, and nothing changes unless the user
approves it there. Every fix has an undo.

Fix ids (what the dashboard and ``iglite fix`` pass):

    profile-public:<ifindex>          set the network to Public       (undo: profile-private:<ifindex>)
    firewall-on:<Domain|Private|Public>  turn Windows Firewall on
    block-port:<tcp|udp>:<port>:<profile|Any>  add a block rule  (undo: remove-rule:<name>)
    stop-service:<name>               stop + disable an optional service (undo: enable-service:<name>)
    disable-llmnr                     turn off LLMNR name lookups     (undo: enable-llmnr)
"""

from __future__ import annotations

import base64
import re
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .store import Store

RULE_GROUP = "IntelGraph Lite"
RULE_PREFIX = "IntelGraph Lite: "

# Optional services that are safe to stop on a typical PC: name (lower) -> what it is.
SAFE_SERVICES = {
    "lanmanserver": "File and printer sharing (SMB server)",
    "termservice": "Remote Desktop",
    "winrm": "Windows Remote Management",
    "ssdpsrv": "SSDP discovery",
    "upnphost": "UPnP device host",
    "fdrespub": "Function Discovery publication",
    "remoteregistry": "Remote Registry",
    "snmp": "SNMP",
    "tlntsvr": "Telnet server",
    "sshd": "OpenSSH server",
    "ftpsvc": "FTP server",
    "w3svc": "IIS web server",
    "wmsvc": "IIS management",
    "vncserver": "VNC server",
    "tvnserver": "TightVNC server",
    "uvnc_service": "UltraVNC server",
}
SAFE_PREFIXES = ("mssql", "mysql", "postgresql", "mongodb", "redis", "elasticsearch")

_PROFILES = {"Domain", "Private", "Public", "Any"}
_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.$-]{1,80}$")
_RULE_RE = re.compile(r"^IntelGraph Lite: [A-Za-z0-9 .:()/_-]{1,100}$")


def stoppable(service: str) -> bool:
    s = service.lower()
    return bool(_SERVICE_RE.match(service)) and (s in SAFE_SERVICES or s.startswith(SAFE_PREFIXES))


def _rule_name(proto: str, port: int, profile: str) -> str:
    return f"{RULE_PREFIX}block {proto.upper()} {port} ({profile})"


def build(fix_id: str) -> dict[str, Any]:
    """Title, PowerShell command and undo id for a fix id. Raises ValueError for anything invalid."""
    action, _, arg = fix_id.partition(":")
    if action in ("profile-public", "profile-private"):
        if not arg.isdigit() or not 0 < int(arg) < 100000:
            raise ValueError("bad interface index")
        cat = "Public" if action == "profile-public" else "Private"
        return {
            "title": f"Set this network to {cat}",
            "command": f"Set-NetConnectionProfile -InterfaceIndex {int(arg)} -NetworkCategory {cat}",
            "undo": f"profile-{'private' if cat == 'Public' else 'public'}:{int(arg)}",
            "why": "Public tells Windows the network isn't trusted: discovery and sharing are blocked."
            if cat == "Public"
            else "Private trusts the network again (discovery and sharing allowed).",
        }
    if action == "firewall-on":
        if arg not in ("Domain", "Private", "Public"):
            raise ValueError("bad profile")
        return {
            "title": f"Turn Windows Firewall on ({arg} networks)",
            "command": f"Set-NetFirewallProfile -Profile {arg} -Enabled True",
            "undo": None,
            "why": "The firewall blocks inbound connections that no rule allows.",
        }
    if action == "block-port":
        proto, _, rest = arg.partition(":")
        port_s, _, profile = rest.partition(":")
        if (
            proto not in ("tcp", "udp")
            or not port_s.isdigit()
            or not 0 < int(port_s) < 65536
            or profile not in _PROFILES
        ):
            raise ValueError("bad port rule")
        port, name = int(port_s), _rule_name(proto, int(port_s), profile)
        return {
            "title": f"Block inbound {proto.upper()} {port}"
            + ("" if profile == "Any" else f" on {profile} networks"),
            "command": (
                f"New-NetFirewallRule -DisplayName '{name}' -Group '{RULE_GROUP}' -Direction Inbound "
                f"-Action Block -Protocol {proto.upper()} -LocalPort {port} -Profile {profile} | Out-Null"
            ),
            "undo": f"remove-rule:{name}",
            "why": "A block rule wins over allow rules: other devices can no longer connect to that port.",
        }
    if action == "remove-rule":
        if not _RULE_RE.match(arg):
            raise ValueError("only IntelGraph Lite's own rules can be removed")
        return {
            "title": f'Remove firewall rule "{arg}"',
            "command": f"Remove-NetFirewallRule -DisplayName '{arg}'",
            "undo": None,
            "why": "Undoes a block rule IntelGraph Lite added.",
        }
    if action in ("stop-service", "enable-service"):
        if not stoppable(arg):
            raise ValueError("not a service IntelGraph Lite will change")
        label = SAFE_SERVICES.get(arg.lower(), arg)
        if action == "stop-service":
            return {
                "title": f"Stop and disable {label} ({arg})",
                "command": f"Stop-Service -Name '{arg}' -Force; Set-Service -Name '{arg}' -StartupType Disabled",
                "undo": f"enable-service:{arg}",
                "why": "A stopped service listens on no port at all; disabling keeps it off after a restart.",
            }
        return {
            "title": f"Re-enable {label} ({arg})",
            "command": f"Set-Service -Name '{arg}' -StartupType Manual; Start-Service -Name '{arg}'",
            "undo": f"stop-service:{arg}",
            "why": "Undoes stopping the service.",
        }
    key = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if action == "disable-llmnr" and not arg:
        return {
            "title": "Turn off LLMNR name lookups",
            "command": (
                f"New-Item -Path '{key}' -Force | Out-Null; "
                f"Set-ItemProperty -Path '{key}' -Name EnableMulticast -Value 0 -Type DWord"
            ),
            "undo": "enable-llmnr",
            "why": "Others on the network can answer LLMNR lookups falsely to capture password hashes.",
        }
    if action == "enable-llmnr" and not arg:
        return {
            "title": "Turn LLMNR back on",
            "command": f"Remove-ItemProperty -Path '{key}' -Name EnableMulticast -ErrorAction SilentlyContinue",
            "undo": "disable-llmnr",
            "why": "Undoes turning LLMNR off.",
        }
    raise ValueError(f"unknown fix {fix_id!r}")


def _profile(adapter: dict[str, Any] | None) -> str:
    p = (adapter or {}).get("profile") or "Any"
    return (
        {"DomainAuthenticated": "Domain"}.get(p, p)
        if p in ("Public", "Private", "DomainAuthenticated")
        else "Any"
    )


def attach(rep: dict[str, Any], applied: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Add ``fix_ids`` to findings and exposure items, and the catalog of offered fixes, to a report."""
    catalog: dict[str, dict[str, Any]] = {}
    if rep.get("platform") != "windows":
        rep["fixes"], rep["applied_fixes"] = {}, applied or []
        return rep

    def offer(fix_id: str) -> str | None:
        try:
            catalog[fix_id] = {"id": fix_id, **build(fix_id)}
            return fix_id
        except ValueError:
            return None

    adapters = {a["name"]: a for a in rep["adapters"]}
    for item in rep["exposure"]["adapters"]:
        profile = _profile(adapters.get(item["name"]))
        for svc in item["listeners"]:
            ids = []
            if svc["reachable"] and svc["risk"] in ("high", "medium"):
                ids.append(offer(f"block-port:{svc['proto']}:{svc['port']}:{profile}"))
                ids += [offer(f"stop-service:{n}") for n in svc.get("service_names") or [] if stoppable(n)]
                if svc["port"] == 5355:
                    ids.append(offer("disable-llmnr"))
            svc["fix_ids"] = [i for i in ids if i]
    for f in rep["findings"]:
        p, ids = f.get("params") or {}, []
        if f["kind"] == "private_profile" and p.get("index") is not None:
            ids.append(offer(f"profile-public:{p['index']}"))
        elif f["kind"] == "firewall_off" and p.get("profile"):
            ids.append(offer(f"firewall-on:{p['profile']}"))
        elif f["kind"] == "exposed":
            profile = _profile(adapters.get(f.get("adapter") or ""))
            for s in p.get("services") or []:
                ids.append(offer(f"block-port:{s['proto']}:{s['port']}:{profile}"))
                ids += [offer(f"stop-service:{n}") for n in s.get("service_names") or [] if stoppable(n)]
        f["fix_ids"] = [i for i in dict.fromkeys(ids) if i]
    rep["fixes"] = catalog
    rep["applied_fixes"] = applied or []
    return rep


# -- running ------------------------------------------------------------------------------

Runner = Callable[[str], tuple[bool, str]]


def powershell_exe() -> str:
    """Windows PowerShell by full path: an elevated run must not pick up a planted powershell.exe on PATH."""
    import os

    root = os.environ.get("SystemRoot", r"C:\Windows")
    return str(Path(root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def run_elevated(command: str, timeout: float = 300) -> tuple[bool, str]:
    """Run PowerShell as administrator. Windows shows the UAC prompt; nothing runs if it's declined."""
    if sys.platform != "win32":
        return False, "fixes run on Windows only"
    log = Path(tempfile.gettempdir()) / f"iglite-fix-{uuid.uuid4().hex}.log"
    lit = str(log).replace("'", "''")
    inner = (
        "$ErrorActionPreference = 'Stop'\ntry {\n"
        + command
        + f"\n'OK' | Out-File -Encoding utf8 -FilePath '{lit}'\nexit 0\n}} catch {{\n"
        f"$_.Exception.Message | Out-File -Encoding utf8 -FilePath '{lit}'\nexit 1\n}}"
    )
    enc = base64.b64encode(inner.encode("utf-16-le")).decode()
    outer = (
        "$p = Start-Process -FilePath powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru "
        f"-ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{enc}'; exit $p.ExitCode"
    )
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.run(  # noqa: S603 - fixed argv; the command is built from validated values only
        [powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", outer],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
        creationflags=flags,
    )
    detail = ""
    try:
        detail = log.read_text(encoding="utf-8-sig", errors="replace").strip()
        log.unlink()
    except OSError:
        pass
    if proc.returncode == 0:
        return True, detail or "OK"
    err = detail or proc.stderr.strip().splitlines()[-1:] or ["failed"]
    msg = err if isinstance(err, str) else err[0]
    if "canceled by the user" in msg.lower() or "cancelled by the user" in msg.lower():
        msg = "You declined the administrator prompt; nothing was changed."
    return False, msg


def apply(fix_id: str, store: Store, runner: Runner | None = None) -> dict[str, Any]:
    """Run one fix and record it (with its undo) in ``localnet.fixes``."""
    fix = build(fix_id)
    ok, output = (runner or run_elevated)(fix["command"])
    if ok:
        history = store.get_meta_json("localnet.fixes") or []
        undo_of = next((h for h in history if h.get("undo") == fix_id and not h.get("undone")), None)
        if undo_of is not None:  # this run undid an earlier fix
            undo_of["undone"] = time.time()
        else:
            history.append({"id": fix_id, "title": fix["title"], "at": time.time(), "undo": fix["undo"]})
        store.set_meta_json("localnet.fixes", history[-100:])
    return {"ok": ok, "output": output, "fix": {"id": fix_id, **fix}}
