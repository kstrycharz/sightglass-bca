# Runtime configuration

`llm.yaml` lands here in M3: provider definitions, role-based model routing,
and egress policy. Hot-reloadable.

Egress defaults to `deny`. Air-gapped mode makes any cloud adapter fail at
config-validation time rather than at request time — a trust boundary that only
fails when it is exercised is not one.
