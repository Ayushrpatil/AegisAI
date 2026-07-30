# AegisAI Dataset Evaluation

Generated: 2026-07-30T00:12:26.503Z

- Total contracts: 143
- Contracts in supported categories: 131
- Supported-category detections: 129
- Supported-category category-level recall: 98.5%
- Unsupported-category files with findings: 9/12

> Access-control coverage is intentionally limited to tx.origin and unprotected ownership initialization; category-level recall is not a claim of general access-control coverage.

| Category | Claimed scope | Dataset files | Evaluation targets | Detected | Detection rate |
| --- | --- | ---: | ---: | ---: | ---: |
| access_control | tx.origin + unprotected ownership initialization | 18 | 6 | 6 | 100.0% |
| arithmetic | full category | 15 | 15 | 15 | 100.0% |
| bad_randomness | full category | 8 | 8 | 8 | 100.0% |
| denial_of_service | full category | 6 | 6 | 6 | 100.0% |
| front_running | full category | 4 | 4 | 4 | 100.0% |
| other | full category | 3 | 3 | 3 | 100.0% |
| reentrancy | full category | 31 | 31 | 29 | 93.5% |
| short_addresses | full category | 1 | 1 | 1 | 100.0% |
| time_manipulation | full category | 5 | 5 | 5 | 100.0% |
| unchecked_low_level_calls | full category | 52 | 52 | 52 | 100.0% |
