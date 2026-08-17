# Synthetic corpus

A build target, not a download. `make corpus` compiles small, purpose-built
vulnerable binaries: a C program with a fake AWS key in a UTF-16 string, a Go
binary leaking its build path, an NSIS installer wrapping a config with a dummy
token, a PyInstaller bundle, a squashfs image with a default password in
/etc/shadow, a .NET assembly with an embedded connection string.

Sources are committed; built artifacts are not. Never commit a real credential
— use provably-invalid shapes.

This corpus is labelled, which makes it the input to the precision/recall
harness. That harness is the single most valuable test asset in the project;
it is built at M2, not M6.
