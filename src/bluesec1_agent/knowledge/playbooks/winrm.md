---
name: WinRM remote session (wsmprovhost.exe)
description: How to tell remote administration over WinRM from an attacker's remote shell.
processes: wsmprovhost.exe
trigger_only: true
keywords: winrm wsmprovhost remote powershell invoke-command enter-pssession 5985 5986
---
wsmprovhost.exe hosts every inbound WinRM/PowerShell-remoting session, so the process itself proves nothing; who opened the session and what it did decide the case.

Check, in this order:
1. Identity of the host process: image in \Windows\System32\, Microsoft signer, parent svchost.exe (the WinRM service). Anything else is masquerading.
2. The inbound connection: a network connection to this host on 5985/5986 just before the session, its source host and address. No inbound WinRM connection while the process runs remote shells is itself a finding to explain.
3. The account and its logon: network logon of which account, from which host; the AD object (description, title, groups) — is it an administrator or a service account meant for this host and task?
4. What the session ran: the child powershell.exe (powershell_host ServerRemoteHost) and its script blocks or cmdlets.

Legitimate: a management or automation host, an admin or service account whose role fits, commands limited to inventory, configuration or health checks on the systems it manages, no follow-on activity.
Attack: an unusual source (workstation, external address), an account outside its role, discovery, credential theft, payload download or execution, persistence, or hops to further hosts.

Report: for benign, cite the inbound connection or logon relation (who initiated), the wsmprovhost/powershell fields that prove identity (image_path, signer, parent_image, powershell_host), and the account's role fields. For malicious, the source host, the account, the session processes and what they dropped or changed.
