# Rule fixtures

Positive and negative test cases, one pair per rule.

Never commit a real credential. Use provably-invalid shapes
(`AKIAIOSFODNN7EXAMPLE`-style). gitleaks runs against this repo in CI, and
shipping a live secret in the repo of a secret scanner would be hard to live
down.
