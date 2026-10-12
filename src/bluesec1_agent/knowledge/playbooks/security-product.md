---
name: Security product process (antivirus, EDR)
description: How to tell an endpoint protection agent's normal behaviour from tampering or an impostor.
processes: msmpeng.exe, mssense.exe, ekrn.exe, egui.exe, avp.exe, sfc.exe, ntrtscan.exe, tmbmsrv.exe, cyveraservice.exe, sentinelagent.exe, csfalconservice.exe, cb.exe, repmgr.exe, savservice.exe, mcshield.exe
trigger_only: true
keywords: antivirus edr lsass handle access granted_access call_trace scan tamper exclusion
---
Protection agents scan memory, open handles to lsass.exe and restart their own workers - behaviour that also matches credential theft rules. Whether it is the genuine product doing its job decides the case.

Check, in this order:
1. Identity: image in the vendor's install directory, valid signature, parent services.exe or the product's own service, and the same hash as on other hosts (prevalence).
2. Access to lsass.exe or other processes: the granted access rights and the call trace. Query-only rights (0x1000, 0x1400) through the vendor's own modules fit scanning; read or full rights (0x10, 0x1010, 0x1410, 0x1fffff), dbghelp/comsvcs MiniDump, or an unknown module in the call trace fit dumping.
3. The product's state: service stopped, exclusions added, drivers unloaded, or files replaced - tampering.
4. Related activity on the host: a dump file written, an archive, or an outbound transfer after the access.

Legitimate when: the genuine signed agent in its directory, consistent across the fleet, with query-level access through its own code and nothing written or sent afterwards.
Attack when: the binary is out of place, differs from the fleet, or is unsigned; access rights allow memory reads; the call trace runs through dump functions; or the product is being disabled.

Report: benign - the agent process (image_path, digital_signature, parent_image), the handle relation fields that show the access was query-only (granted_access, call_trace), and the host. Malicious - the impostor or dumping process, the dump file, the host and any account exposed.
