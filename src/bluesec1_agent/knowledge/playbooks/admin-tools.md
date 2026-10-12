---
name: Administrative tools (mmc.exe, net.exe, net1.exe)
description: How to tell directory and system administration from discovery or privilege abuse with the same tools.
processes: mmc.exe, net.exe, net1.exe
trigger_only: true
keywords: mmc dsa.msc gpmc net user net group localgroup domain admins administration
---
Admin consoles and net commands are used daily by administrators and by attackers alike; the tool proves nothing. Who ran it, from where, and what it changed decide the case.

Check, in this order:
1. The command: the console or snap-in, or the exact net arguments (query or change, which account or group).
2. The account: is it an administrator or service account whose role covers this action (groups, privilege, description)? An ordinary user running domain queries or group changes needs explaining.
3. The host and session: an admin workstation or server versus an ordinary user endpoint; interactive session versus a shell spawned by Office, a browser, a script host or a remote shell.
4. What followed: group membership changes, new accounts, password resets, and whether they match a request or a pattern of routine work.

Legitimate when: an administrator on an admin host, interactive, performing changes consistent with their role, without a burst of enumeration.
Attack when: rapid discovery (net user /domain, net group "domain admins", net localgroup administrators) from an unusual parent, a user or service account outside its role, adding accounts to privileged groups, or the same account later used for remote access.
Looks similar but legitimate: helpdesk resets and group changes from a management console; scripted onboarding run by a provisioning account.

Report: benign - the tool process (image_path, cmdline, parent_image), the account entity that shows authority (username, groups, privilege), and the host's role. Malicious - the account abused, the host, the discovery or change commands, and any account or group modified.
