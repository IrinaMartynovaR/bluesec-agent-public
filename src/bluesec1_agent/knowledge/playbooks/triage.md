---
name: Triage of any alert - the alert is a pointer, not the case
description: The order every investigation follows, how to look next to the alert, and how to tell background noise from signal.
always: true
keywords: triage alert pointer neighbourhood session host timeline noise background signal
---
An alert marks one event. The case is what happened around it: an attack often sits next to the alerted process (a document opened in the same session, a client connecting to the alerted service, a sibling launched by the same parent), and a frightening alert is often routine work.

1. Establish the fact: what exactly ran or connected, as which account, on which host, when. The fact is not yet a verdict.
2. Look next to it before judging it: the same logon session and host in the alert's time window (the process tables above), the trigger's parent and children, files it wrote and who opened them, and for a service or kernel process the clients that connected to it. Judge the trigger only after the neighbourhood.
3. Separate background from signal. Background repeats and fits the host: developer tools (git, node, npm, kubectl, docker, IDEs, compilers, test runners), browsers and their helper processes, Windows services and updates, security agents, scheduled jobs that recur at a fixed interval, signed software in Program Files. Signal is rare and breaks the pattern: a child of an Office application, browser, mail client or script host; an encoded, hidden or download-and-run command; a binary in a user-writable path or with a mismatched name; archive creation, credential access or memory dumps; new services, tasks or Run keys; a single source connecting where many clients would be normal; an account acting outside its role. One signal line among a hundred background lines decides the case.
4. Turn what you read into entities. A script body or command line explains the activity, but the report is scored on the entities you open: every account, host, address, mailbox, share, file or script that a command or script names - the account a share is mounted with, the server data is sent to, the mailbox a script reads - search for it by that value and open it. Reading the next script block or the same file again rarely adds anything new; opening what it names does.
5. Hold two explanations, legitimate and malicious, and pick each call to tell them apart. Neither a signed binary nor a scary name settles it; the neighbourhood and the account's role do.
6. Stop when the entry point, the impact and the strongest signal are resolved one way or the other.
