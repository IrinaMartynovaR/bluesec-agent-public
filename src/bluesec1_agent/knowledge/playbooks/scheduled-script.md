---
name: Script launched by Task Scheduler or Group Policy
description: How to tell centrally deployed automation from attacker persistence that uses the same mechanism.
processes: powershell.exe, cmd.exe, wscript.exe, cscript.exe
parents: svchost.exe, gpscript.exe, taskeng.exe
trigger_only: true
keywords: scheduled task schtasks svchost schedule group policy gpo netlogon sysvol logon script automation
---
Apply this when the trigger's parent is the Task Scheduler (svchost.exe -k netsvcs -s Schedule) or Group Policy (gpsvc), or the command runs a script from NETLOGON/SYSVOL. Scheduler and policy launch both inventory jobs and persistence; the task's origin and the script's content decide.

Check, in this order:
1. The task or policy: which scheduled task (name, action, run-as account, trigger) and who created it - a group policy refresh from a domain controller, an admin tool, or a process on this host shortly before.
2. The script: path (SYSVOL/NETLOGON or a program directory versus a user-writable path), and its content (script blocks): inventory, configuration or maintenance versus download, encoded commands, credential access, or changes to privileged groups and ACLs.
3. The run-as account: a service account whose description or groups fit the job, and whether its rights match what the script changes.
4. The pattern: the same job recurring on schedule and on other hosts versus a single new run.

Legitimate when: the task comes from policy or an admin, the script is centrally stored and does what its name and the account's purpose say, and it recurs as designed.
Attack when: the task was created from a user session or by a script host, the script sits in a user-writable path, it downloads or decodes code, or it grants rights the account's stated purpose does not cover.
Looks similar but legitimate: hardware or software inventory, AD tiering or cleanup jobs run by dedicated service accounts, patch and configuration scripts.

Report: benign - the scheduled task or policy object (task_name, action_target, run_as_account), the script (path), the run-as account entity (username, groups), and the trigger process (image_path, parent_image, cmdline). Malicious - the task as persistence_to_remove, the script and payloads, the account and host.
