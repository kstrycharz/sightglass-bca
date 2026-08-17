# Ghidra headless scripts

Passed to `analyzeHeadless` via `-scriptPath`. They export xrefs to flagged
strings, hardcoded crypto constants, and decompiled context windows.

Decompile only what the correlator flagged: decompiling everything is both slow
and useless. Ghidra is the most likely source of OOMs and timeouts in the whole
pipeline — treat it as best-effort enrichment, never a hard dependency.
Scheduled M5.
