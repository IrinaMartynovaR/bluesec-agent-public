---
name: Collection, staging and exfiltration of data
description: How to trace archives and staged data from collection to the place they left the host.
entity_types: archive_file
keywords: archive staging collection exfiltration compress-archive 7z rar zip makecab rclone upload stolen data mailbox outlook mapi webdav net use
---
Archives created during an incident are usually the attacker's staging step before data leaves. Trace them in both directions.

Check, in this order:
1. Which process created the archive (file write or archive relation) and with what command line; is it a legitimate backup or packaging tool run by its usual account, or a shell or script run interactively by an attacker?
2. What went into it: the files or directories it archived (contains or archived-to relations, source paths). Business data from shares or user folders is collection.
3. Where it went next: the processes that read the archive afterwards, network connections from those processes (uploads, curl or PowerShell web requests, rclone, cloud sync), and mounted shares or removable volumes it was copied to.
4. Clean-up: deletion of the archive or the working directory after transfer.
5. The other side of the theft, as entities: when mail was collected, the mailbox and the messages it read; when data left to a server, that server's host and the connection to it; when a share or cloud service was used with an account, that account as an entity (search its name or address). These are part of the incident, not only details of the story.

Report: the archive is evidence of collection, not something to restore; report the attacker processes, the tooling files they dropped (file_to_delete), the destination endpoint (network_block), the compromised host and account, and the mailbox whose mail was collected (mailbox_action). Victim documents that were read or archived are not files to delete.
