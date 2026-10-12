---
name: Logon session start (userinit.exe, explorer.exe)
description: How to tell a normal user logon from logon-time persistence or a hijacked shell.
processes: userinit.exe, explorer.exe
trigger_only: true
keywords: userinit explorer winlogon logon shell logon script gpo
---
userinit.exe and explorer.exe start with every interactive logon, so their start proves only that someone logged on. The question is whether the logon and what it launched are expected.

The fact of the event is not the verdict: establish it first, then decide whether it is malicious.

Check, in this order:
1. Lineage: userinit.exe from winlogon.exe, explorer.exe from userinit.exe, both Microsoft-signed in \Windows\. A different parent or path is masquerading.
2. The logon behind the session: logon type (interactive, remote interactive), source host or address, the account and its groups and privilege.
3. What the session launched in its first minutes: logon scripts (from NETLOGON/SYSVOL), startup items, and their command lines.
4. Logon-time configuration: Winlogon Userinit/Shell values, Run keys or startup folders written shortly before.

Legitimate when: a known user logs on from an expected place, the lineage is standard, and what runs at logon is the domain's logon scripts or installed software.
Attack when: Userinit or Shell points at an extra program, a logon launches a payload or an encoded/download command, the logon comes from an unexpected source, or the account has no reason to log on to this host.
Looks similar but legitimate: roaming profile or GPO logon scripts that run cmd/powershell; IT-installed agents starting at logon.

Report: benign - the session's processes with image_path and parent_image, the account entity with the fields that show who it is (username, groups, privilege), and the logon-script or software object that explains what ran. Few decisive fields per item. Malicious - the modified registry value or file, the payload process, the host and account.
