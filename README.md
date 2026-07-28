# AegisAI

AegisAI is an explainable, deterministic security scanner for Solidity smart
contracts. It helps developers move from a warning to an actionable fix by
showing:

- the exact source lines that triggered a rule,
- severity and confidence,
- a plain-language explanation,
- a likely attack path, and
- constrained remediation guidance.

The current version is a local-first educational prototype. It does not upload
source code, prove that a contract is safe, or replace a professional audit.

## Live deployment

Try AegisAI online: [aegisai-smart-contract-scanner.vercel.app](https://aegisai-smart-contract-scanner.vercel.app/)

## Working prototype

The v0.1 scanner detects eleven patterns:

1. Reentrancy risk caused by an external value call before a state update
2. `tx.origin` authorization
3. Unchecked low-level calls
4. Unprotected ownership initialization, including misnamed legacy constructors
5. Denial of service caused by required external payments, unbounded
   storage-writing loops, or single-transaction collection cleanup
6. Predictable randomness derived from block metadata
7. Timestamp-sensitive outcomes and state transitions
8. Unchecked overflow and underflow in legacy Solidity
9. Transaction-order dependence and front-running exposure
10. Legacy short-address ABI ambiguity
11. Uninitialized storage references

The primary workflow accepts one or more real local `.sol` files (up to 1 MB
each and 2 MB combined) or pasted Solidity source. The browser reads and scans
the actual file contents locally;
the source is never uploaded. The interface also includes optional vulnerable
and corrected examples, a risk summary, line-level evidence, reviewed
explanation templates, JSON export, and a printable standalone HTML report.

When run with `npm run dev`, the local analyzer uses the official JavaScript
Solidity compiler (`solc-js`) to validate the uploaded source and return genuine
compiler errors and warnings before applying the AegisAI evidence rules. If the
API is unavailable, the interface clearly labels the result as a browser-rule
fallback.

The analyzer reads the source file's `pragma solidity` declaration and selects a
bundled compiler family. Solidity 0.4.x contracts use pinned `solc` 0.4.26,
Solidity 0.5.x contracts use pinned `solc` 0.5.17, and modern contracts use the
current 0.8.x compiler. Exact 0.4.x pragmas are relaxed only in the temporary
compiler input and recorded as normalized; the uploaded source and security scan
remain unchanged. Solidity 0.6.x and 0.7.x use pinned compatible compilers.

```text
Solidity source
      ↓
Deterministic rule adapter
      ↓
Normalized evidence and severity
      ↓
Template explanation adapter
      ↓
Readable report + JSON export
```

## Run locally

Requirements: Node.js 18 or newer.

```powershell
npm install
npm run dev
```

Open the local URL printed by Vite.

## Test and build

```powershell
npm test
npm run build
npm run evaluate
```

### Optional Slither analysis

If `slither-analyzer` is installed separately, normalize its deeper control-flow
results into the AegisAI report shape:

```powershell
npm run scan:slither -- Contracts/MyContract.sol reports/slither-report.json
```

Slither is optional; the local deterministic scanner does not depend on Python.
The bridge checks the uploaded contract's pragma against the active global
`solc` and prints the exact `solc-select` command when they do not match.

Verified example:

```powershell
solc-select use 0.4.26
npm run scan:slither -- .\Contracts\dataset\reentrancy\etherstore.sol .\reports\slither-report.json
```

This produces normalized evidence including Slither's high-severity
`reentrancy-eth` finding.

### Optional grounded explanation service

`server/explanation-adapter.js` keeps reviewed rule templates as the default.
An external explanation endpoint can be enabled with
`AEGIS_EXPLANATION_ENDPOINT`. The adapter sends only an already-detected
finding and its evidence, instructs the service not to invent new findings, and
retains the deterministic rule ID as provenance.

The automated tests verify all eleven supported detectors, the corrected sample,
comment handling, and the presence of evidence and remediation fields.

## Dataset evaluation

The repository includes 143 labeled SmartBugs-style contracts under
`Contracts/dataset`. AegisAI is deterministic, so the dataset is used for
evaluation and rule refinement—not opaque model training.

The generated reports are:

- `reports/dataset-evaluation.md`
- `reports/dataset-evaluation.json`

Current results for the 131 contracts inside the explicitly claimed scope:

| Detector scope | Targets | Detected | Recall |
| --- | ---: | ---: | ---: |
| `tx.origin` and ownership initialization | 6 | 6 | 100% |
| Legacy arithmetic | 15 | 15 | 100% |
| Predictable randomness | 8 | 8 | 100% |
| Denial of service | 6 | 6 | 100% |
| Front-running | 4 | 4 | 100% |
| Uninitialized storage | 3 | 3 | 100% |
| Short-address ABI | 1 | 1 | 100% |
| Timestamp dependence | 5 | 5 | 100% |
| Reentrancy | 31 | 29 | 93.5% |
| Unchecked low-level calls | 52 | 52 | 100% |
| **Overall claimed scope** | **131** | **129** | **98.5%** |

The two remaining reentrancy misses require modifier or cross-function analysis.
They are documented rather than hidden because adding a broad text match would
increase false positives. Findings in unsupported folders are reported
separately and are not presented as proof of correctness.

## Project structure

| Path | Purpose |
| --- | --- |
| `server/analyze.js` | Solidity compiler adapter and normalized report assembly |
| `server.mjs` | Local compiler-backed scan API |
| `src/scanner.js` | Deterministic security rules and normalized finding schema |
| `src/samples.js` | Vulnerable and corrected Solidity demonstrations |
| `src/app.js` | Browser interface and JSON report export |
| `src/styles.css` | Responsive presentation layer |
| `test/scanner.test.js` | Node-based detector tests |
| `scripts/evaluate-dataset.mjs` | Reproducible batch evaluation over all dataset contracts |
| `reports/` | Machine-readable and Markdown evaluation results |
| `Final_Project_Proposal_AegisAI_Revised.docx` | Written proposal |
| `AegisAI_Project_Proposal.pptx` | Proposal presentation |

## Trust and limitations

- Solidity syntax and compiler diagnostics come from `solc-js`.
- Compiler success and security-rule success are separate: a contract can
  compile correctly while containing a vulnerability outside the eleven supported
  detector classes.
- Security findings come from explicit evidence rules, not from an unconstrained language model.
- “AI-assisted” explanations are currently reviewed templates grounded in each
  rule and its source evidence.
- The prototype does not analyze inheritance, cross-file flows, inline assembly,
  proxies, every denial-of-service form, front-running, or every reentrancy form.
- A clean report means only that the supported patterns were not found.

## Next milestones

- Add AST- and control-flow-aware handling for the two remaining advanced
  reentrancy cases.
- Resolve imported dependencies as true multi-file compiler sources instead of
  concatenating selected files for the prototype workflow.
- Add authenticated repository scanning with explicit size and dependency
  limits.
- Run a precision study on labeled safe contracts in addition to the current
  vulnerable-contract recall evaluation.

## Proposal artifacts

The repository also contains the complete Word proposal, the proposal slide
deck, and their generation helpers.

Final presentation content and the live-demo script are documented in
`FINAL_PRESENTATION_NOTES.md`. Deployment and release checks are documented in
`DEPLOYMENT.md`.

## Author

Ayush Patil
