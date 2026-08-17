# Report templates

One rendering path, not two: the PDF is a headless-Chromium render of a
dedicated print stylesheet over the same HTML the dashboard uses. A separate
ReportLab implementation drifts from the dashboard within a release or two.

Output must be deterministic — pin fonts, freeze timestamps — so a report can
be hash-attested. Scheduled M4.
