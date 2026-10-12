"""Structural facts about graph entities, computed without attack knowledge.

Knowledge about techniques (command lines, parent/child pairs, LOLBins) comes from
the detection knowledge base (`knowledge.py`), not from hand-written patterns here.
This module only states facts that follow from the data itself: where a binary runs
from compared to where it belongs, whether it is signed, whether its file was
renamed, and whether an address is external. Both directions are reported, so a
legitimate binary in its place is as visible as a misplaced one.
"""

import ipaddress
import re
from typing import Any

SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\")
# Core Windows binaries that only ever run from the system directories.
SYSTEM_BINARIES = {
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "csrss.exe",
    "winlogon.exe",
    "smss.exe",
    "wininit.exe",
    "spoolsv.exe",
    "taskhostw.exe",
    "dllhost.exe",
    "conhost.exe",
    "wsmprovhost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "cmd.exe",
    "powershell.exe",
    "msiexec.exe",
    "wmiprvse.exe",
}
MICROSOFT_SIGNERS = ("microsoft",)
USER_WRITABLE_MARKERS = (
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\perflogs\\",
    "\\$recycle.bin\\",
    "\\programdata\\",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
)
# Facts a benign verdict has to account for; the rest are context.
STRONG_SIGNAL_MARKERS = ("masquerading", "renamed binary", "beaconing", "lookalike")
# Characters an impersonator swaps in for the ones they imitate: Cyrillic letters drawn
# like Latin ones, and digits or symbols read as letters.
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "в": "b",
        "е": "e",
        "к": "k",
        "м": "m",
        "н": "h",
        "о": "o",
        "р": "p",
        "с": "c",
        "т": "t",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "0": "o",
        "1": "l",
        "|": "l",
        "!": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "$": "s",
        "@": "a",
    }
)
MIN_EDIT_NAME = 6
EXECUTABLE_SUFFIX = r"\.(exe|dll|sys|scr|com|ps1|bat|cmd|vbs|js|msi)$"
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def entity_signals(entity_type: str | None, properties: dict[str, Any]) -> list[str]:
    """Return structural facts for one entity.

    Args:
        entity_type: Graph entity type, e.g. `windows_process`.
        properties: Non-empty entity properties.

    Returns:
        Short factual statements prefixed with `suspicious:` or `benign:`.
    """
    if entity_type in {"windows_process", "linux_process"}:
        return _process_signals(properties)
    if entity_type == "network_connection":
        return _connection_signals(properties)
    if entity_type in {"windows_user", "linux_user", "host"}:
        name = str(properties.get("username") or properties.get("hostname") or "")
        if mixed_scripts(name):
            return [f"suspicious: name {name!r} mixes Latin and other scripts (lookalike)"]
        return []
    if entity_type in {"windows_file", "linux_file"} and _user_writable(
        str(properties.get("path", "")).lower()
    ):
        return ["suspicious: file in a user-writable location"]
    return []


def skeleton(name: str) -> str:
    """A name with lookalike characters folded to the letters they imitate."""
    folded = name.lower().translate(CONFUSABLES).replace("rn", "m").replace("vv", "w")
    return folded.replace("i", "l")


def mixed_scripts(name: str) -> bool:
    """Whether a name mixes Latin letters with non-ASCII letters (e.g. Cyrillic)."""
    letters = [char for char in name if char.isalpha()]
    return any(char.isascii() for char in letters) and any(not char.isascii() for char in letters)


def one_edit_apart(first: str, second: str) -> bool:
    """Whether two different strings differ by one insertion, deletion, swap or change."""
    if first == second or abs(len(first) - len(second)) > 1:
        return False
    if len(first) == len(second):
        diff = [index for index, (a, b) in enumerate(zip(first, second, strict=True)) if a != b]
        if len(diff) == 1:
            return True
        return (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and first[diff[0]] == second[diff[1]]
            and first[diff[1]] == second[diff[0]]
        )
    shorter, longer = sorted((first, second), key=len)
    return any(longer[:index] + longer[index + 1 :] == shorter for index in range(len(longer)))


def lookalike(name: str, genuine: str, same_length: bool = False) -> bool:
    """Whether a name imitates another: same skeleton, or one edit apart.

    Names that differ only in digits (user01, user02) are ordinary numbering, and a
    different first character (a.turner, m.turner) is usually a different person.
    same_length: count only a changed or swapped letter, not an added or dropped one.
    """
    a, b = name.lower(), genuine.lower()
    if a == b or len(b) < 5:
        return False
    if re.sub(r"\d", "", a) == re.sub(r"\d", "", b):
        return False
    if skeleton(a) == skeleton(b):
        return True
    # A one-letter slip is only telling on a name long enough to be distinctive
    # (ssms.exe and smss.exe are two different, ordinary programs).
    core = [re.sub(EXECUTABLE_SUFFIX, "", value) for value in (a, b)]
    if min(map(len, core)) < MIN_EDIT_NAME or a[0] != b[0]:
        return False
    if same_length and len(a) != len(b):
        return False
    # A digit in place of a letter is numbering unless it reads as that letter, which
    # the skeleton above already catches.
    if any(x != y and (x.isdigit() or y.isdigit()) for x, y in zip(a, b, strict=False)):
        return False
    return one_edit_apart(a, b)


def _process_signals(properties: dict[str, Any]) -> list[str]:
    """Facts about where and how a process binary runs."""
    signals: list[str] = []
    image = str(properties.get("image_path", "")).lower()
    name = _basename(image)
    signer = str(properties.get("signer") or properties.get("company") or "").lower()
    original = str(properties.get("original_filename", "")).lower()
    in_system_dir = any(directory in image for directory in SYSTEM_DIRS)
    microsoft_signed = any(vendor in signer for vendor in MICROSOFT_SIGNERS)

    if name in SYSTEM_BINARIES and image and not in_system_dir:
        signals.append(f"suspicious: {name} runs outside the system directory (masquerading)")
    if name and name not in SYSTEM_BINARIES:
        imitated = next(
            (real for real in SYSTEM_BINARIES if lookalike(name, real, same_length=True)), None
        )
        if imitated:
            signals.append(f"suspicious: {name} imitates {imitated} (lookalike name)")
    if mixed_scripts(image):
        signals.append("suspicious: binary path mixes Latin and other scripts (lookalike)")
    # Some Windows tools ship under another internal name (systeminfo.exe is sysinfo.exe).
    if (
        original
        and name
        and _stem(original) != _stem(name)
        and not (in_system_dir and microsoft_signed)
    ):
        signals.append(f"suspicious: renamed binary (original file name {original})")
    if properties.get("signed") is False:
        signals.append("suspicious: unsigned binary")
    if _user_writable(image):
        signals.append("suspicious: executes from a user-writable location")
    if not signals and in_system_dir and microsoft_signed:
        signals.append("benign: Microsoft-signed binary in its system directory")
    return signals


def _connection_signals(properties: dict[str, Any]) -> list[str]:
    """Facts about a network connection's endpoints."""
    signals = []
    for field in ("dst_ip", "src_ip"):
        value = properties.get(field)
        if isinstance(value, str) and is_external(value):
            direction = "to" if field == "dst_ip" else "from"
            port = properties.get("dst_port")
            signals.append(f"suspicious: connection {direction} external address {value}:{port}")
    return signals


def is_external(address: str) -> bool:
    """True for globally routed or documentation-range addresses."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    # Documentation ranges (RFC 5737) stand in for internet hosts in synthetic data.
    if any(ip in network for network in DOCUMENTATION_NETWORKS):
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)


def _user_writable(path: str) -> bool:
    """True for paths an unprivileged user can write to, minus Microsoft's own data."""
    if "\\programdata\\microsoft\\" in path:
        return False
    return any(marker in path for marker in USER_WRITABLE_MARKERS)


def _basename(path: str) -> str:
    """Last path component in lower case."""
    return re.split(r"[\\/]", path.strip().strip('"'))[-1] if path else ""


def _stem(name: str) -> str:
    """File name without extension."""
    return name.rsplit(".", 1)[0]
