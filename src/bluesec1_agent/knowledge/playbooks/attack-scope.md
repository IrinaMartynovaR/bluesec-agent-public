---
name: Scoping an attack
description: How to find every host and account an intrusion reached before reporting it.
keywords: lateral movement scope scoping compromised hosts accounts pivot psexec wmi winrm rdp logon same account
---
Response is only as good as its scope: a missed host or account stays compromised.

From the confirmed attacker activity, look for reach:
1. Accounts: every account the attacker used, created, or whose credentials were exposed (dumps, plaintext in command lines, Kerberos tickets). Then where else each account logged on.
2. Remote execution and access from the compromised host: outbound connections to admin ports (SMB 445, RPC 135, WinRM 5985/5986, RDP 3389, SSH 22), remote services or tasks, WMI or PsExec-style execution, shares opened.
3. Inbound: which host the attacker came from (logon source, inbound connection), and whether that host is also compromised.
4. The same tool, hash, file name or command on other hosts.

Report every compromised host (host_to_isolate) and every compromised or abused account (identity_to_rotate), and leave out hosts and accounts the attacker did not reach. The host a logon or connection came from is compromised only when attacker activity is seen on it (its processes, tools, or onward logons); an address in a logon record alone does not show that.

Processes: report as process_observed the alert's process and the processes whose own action had an effect (copied, staged, changed or sent data, harvested credentials, installed persistence, connected out). A shell, interpreter or parent that only launched them is part of the story in the reasoning, not an artifact.
