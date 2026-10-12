---
name: Proving that activity is legitimate
description: What a benign conclusion has to show and how to report it as a few decisive facts.
keywords: benign legitimate false positive legitimacy evidence admin maintenance automation
---
A benign verdict is a claim that needs evidence as strong as an attack would. It must answer every suspicious fact, not describe everything that looked normal.

Establish, from the graph:
1. Who initiated it: the logon, inbound connection, scheduled task or service that started the activity, and from where (relation).
2. What ran: the binary's identity (image_path, signer, original_filename) and its parent chain are the expected ones for this activity.
3. Who it ran as: the account and its role (AD description, title, groups) fit the action and the host's role.
4. What it did: the actions match the stated purpose (maintenance, inventory, update, build, browsing) and nothing followed (no new persistence, credential access, unusual outbound traffic, payloads).
5. Each suspicious signal is explained by one of the facts above.

Report at most 3 items, most decisive first: the trigger process with the fields that prove its identity; the account entity it ran as, when that is a named person or service account (cite its role, groups or description - who acted is what makes an action authorized; a built-in account such as SYSTEM or NETWORK SERVICE says nothing about authorization and is not cited); then the entity or relation that explains the strongest signal or gives the activity its purpose. Do not list every entity you looked at: every extra item lowers the report's precision.
