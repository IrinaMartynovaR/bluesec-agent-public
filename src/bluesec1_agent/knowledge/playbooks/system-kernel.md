---
name: Kernel process System (PID 4) - SMB and kernel activity
description: How to investigate alerts on the System process, which owns SMB file sharing and kernel activity on a host.
processes: system
trigger_only: true
keywords: system pid 4 smb 445 139 file share lanmanserver admin share null session ntlm logon
---
System (PID 4) is the kernel. It never runs an attacker's code by itself, but every inbound SMB session, share access and kernel-driven file write is attributed to it. The process proves nothing; the case is about the clients and what they did through it.

Check, in this order:
1. The inbound connections: the source hosts and addresses of the SMB/139/445 sessions accepted by this host, their number and their timing.
2. The sources themselves: role and location of each source host (external, workstation, server), and whether one source talks to many hosts or ports (scanning) or many clients use the share in an ordinary way.
3. The accounts: which accounts logged on over the network from those sources, failed or repeated logons, null sessions, privileged accounts, accounts used outside their usual hosts.
4. What the sessions did: files written to shares (especially executables, scripts, ADMIN$ or C$), services or tasks created remotely, files read in bulk, and what later executed what was written.

Legitimate when: many internal clients reading and writing ordinary files on a file server, with their own accounts, at a normal pace.
Attack when: a single unusual or external source, scanning or enumeration, password guessing or credential use from an unexpected host, writes to admin shares, remote service creation, or bulk collection followed by transfer out.

Report: benign - the System process (image_path, user) and one or two connections or accounts that show ordinary clients. Malicious - the source host and the accounts it used, this host (host_to_isolate), the files dropped or services created, and the attacker endpoint.
