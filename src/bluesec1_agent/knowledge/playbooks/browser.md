---
name: Web browser process (chrome.exe, msedge.exe, firefox.exe)
description: How to find whether a browser alert hides a download-and-execute chain next to ordinary browsing.
processes: chrome.exe, msedge.exe, firefox.exe, iexplore.exe, brave.exe, opera.exe
trigger_only: true
keywords: browser download drive-by attachment office macro zone identifier
---
Browsers make hundreds of connections and are almost always legitimate in themselves; a browser alert is usually a pointer to what the user received. The question is what reached the user through the browser and what ran because of it - and that is often not a child of the browser: a document saved by the browser and opened later by Office starts its own chain in the same session. Do not spend calls on the browser's own connections before the session is checked.

Check, in this order:
1. Children of the browser: any shell, script host or unknown binary started by it.
2. Files the browser wrote (downloads), and processes that opened or executed them afterwards - an Office document opened from Downloads that spawns a script host is the classic chain.
3. The user's session after the browser started: processes in the same logon session and time window, especially Office children, encoded or hidden PowerShell, and tools from user-writable paths.
4. Connections that stand out from browsing: an endpoint contacted only by a non-browser process, or after a download.

Legitimate when: no children, no executed download, and the session after the alert holds only ordinary work.
Attack when: a download is executed or opened and leads to a script, payload, staging or outbound transfer - then report that chain, not the browser.

Report: benign - the browser process (image_path, signer, parent_image) and the session context that shows ordinary activity. Malicious - the document or download, the processes it led to, the C2 or exfiltration endpoint, the host and account.
