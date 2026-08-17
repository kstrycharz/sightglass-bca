# Detection rules

YAML rule files with metadata: id, severity, cwe, description, remediation
template, and test cases. Seeded in M1, expanded through M2.

Every rule ships with at least one positive and one negative fixture in
`fixtures/`. No rule merges without both — an untested rule is how a scanner
acquires the false-positive rate that makes people mute it.
