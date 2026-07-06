# Quality and safety

This repository uses automated checks to reduce the risk of publishing unsafe content.

Checks include:

- PSScriptAnalyzer
- Pester repository tests
- secret scanning
- public safety scanning for common unsafe patterns

The public safety check is intentionally conservative. Generated reports and customer-specific output should not be committed.
