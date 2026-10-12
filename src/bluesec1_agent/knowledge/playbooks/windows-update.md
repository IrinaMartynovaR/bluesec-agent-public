---
name: Windows servicing and update activity (svchost and update components)
description: How to attribute svchost or installer activity to Windows Update/WSUS servicing, or reject that attribution.
trigger_only: true
processes: svchost.exe, tiworker.exe, trustedinstaller.exe, wuauclt.exe, usoclient.exe, mousocoreworker.exe, waasmedicagent.exe, wusa.exe, dism.exe, compattelrunner.exe, mpsigstub.exe, sedlauncher.exe, sedsvc.exe
keywords: windows update wsus wuauserv usosvc bits dosvc cryptsvc trustedinstaller servicing 8530 8531 svchost netsvcs
---
Many Windows components legitimately write files and registry keys and talk to update servers. Attribute activity to servicing only when the whole chain supports it.

Check, in this order:
1. The writer process and its parent and grandparent (up to three levels): are they known update components (TiWorker, TrustedInstaller, wuauclt, usoclient, MoUsoCoreWorker, WaaSMedicAgent, wusa, dism, Defender signature stubs) or svchost.exe hosting an update service?
2. For svchost.exe, the service in its command line (-k group, -s service): wuauserv, UsoSvc, BITS, DoSvc, CryptSvc and TrustedInstaller are servicing; other services are not.
3. Every component in the chain: image in the system directory, Microsoft signer, matching original file name. One unsigned or misplaced component breaks the attribution.
4. Network side: update traffic goes to the organisation's WSUS (HTTP 8530 / HTTPS 8531) or to Microsoft update endpoints; repeated connections to a single unusual external address are not update traffic.

Legitimate: the full chain is Microsoft servicing components hosting update services, talking to the configured update infrastructure.
Attack: a svchost.exe outside System32, a service name that is not a servicing service, an unsigned or renamed component in the chain, a shell or script host spawned from the chain, or traffic to an endpoint no other host uses.

Report: for benign, cite the process (image_path, cmdline with the service name, signer) and its parent chain, and the connection to the update server. For malicious, the misattributed process, what it ran or wrote, and the endpoint it contacted.
