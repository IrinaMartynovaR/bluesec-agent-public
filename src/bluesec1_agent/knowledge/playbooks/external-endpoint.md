---
name: Triage of an external network endpoint
description: How to decide whether connections to an external address are normal traffic, command and control, or exfiltration.
signals: beaconing
keywords: c2 command and control beacon beaconing exfiltration external connection dns sni cdn prevalence reverse check
---
An external connection is only a lead. What decides is who talks to the endpoint, how, and what moved.

Check, in this order:
1. The process behind the connection (follow the connection's relations): its image, signer, parent and command line. A script host, a binary from a user-writable path or a freshly dropped file talking out is a strong signal.
2. Prevalence (reverse check): search the address or domain to see which other hosts and processes contacted it. Many hosts and ordinary software point to shared infrastructure (CDN, update, SaaS); a single process on a single host points to attacker infrastructure.
3. Pattern: repeated connections at regular intervals to the same endpoint are beaconing, even from a signed process (injection, hijacked browser). A burst of large outbound transfers right after staging is exfiltration.
4. Name resolution and TLS: the domain the address was resolved from (DNS), the server name in TLS (SNI). A domain that imitates a vendor, a raw IP over HTTPS, or a mismatch between name and use are signals.
5. What preceded and followed: a download that produced a file or process, an upload of an archive or staged data.

Report: for malicious, network_block only for the attacker-controlled endpoints (the connection entities to them), plus the process that used them. For benign, cite the process identity and the prevalence or destination facts that show ordinary traffic.
