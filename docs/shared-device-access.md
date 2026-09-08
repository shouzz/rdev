# Shared Feidu device access

Authenticated Feidu release accounts share all Feidu managed devices. The control API accepts canonical positive account IDs in `feidu-user:<id>` and `feidu-browser:<id>` subjects, including an operator different from the enrollment owner. The control token is still required; public callers cannot choose an account subject to bypass authentication.

Access tickets retain the actual operator subject, device credential version, connected instance, capability set and expiry. Revocation, credential rotation, stale instances and unsupported capabilities continue to fail closed. Cloud dispatch uses the same device access rule. Other managed subject namespaces retain exact-owner access.

Device registration ownership and explicit same-owner replacement remain enforced. Public launchers allocate a distinct ID for each fresh installation, even when computer names and owners match; repeat persistent installation reuses its protected local identity. Feidu independently authenticates each account and keeps enrollment claims, browser renewals, Agent sessions, cloud tasks and artifact ACLs scoped to their actual account.

Deploy this server together with the Feidu shared-access change. Existing feidu.16 clients remain compatible and do not need re-enrollment. Keep the previous image, Compose file and a consistent data backup for rollback.
