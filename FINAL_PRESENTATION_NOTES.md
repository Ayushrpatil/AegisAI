# AegisAI Final Presentation

## Slide 1 — AegisAI turns Solidity warnings into actionable fixes

**Claim:** Smart-contract scanners should show developers what is wrong, why it
matters, and how to fix it.

**Say:** “I built AegisAI, a local explainable security scanner for real
Solidity contracts. It compiles uploaded source, detects deterministic
vulnerability patterns, links every finding to evidence, and produces an attack
path and remediation.”

## Slide 2 — Existing tools create a comprehension gap

- Smart-contract bugs can permanently lose funds.
- Compiler messages describe syntax and type problems, not complete security.
- Static analyzers often produce expert-oriented output.
- Unconstrained AI can invent vulnerabilities or fixes.

**Say:** “The problem is not only finding a warning. Developers also need
evidence they can verify and guidance that stays tied to that evidence.”

## Slide 3 — The pipeline keeps detection deterministic

```text
Real .sol files
      ↓
Pragma-aware Solidity compiler (0.4–0.8)
      ↓
11 deterministic evidence rules
      ↓
Normalized finding schema
      ↓
Reviewed or opt-in grounded explanation
      ↓
UI + JSON/HTML report
```

Optional path:

```text
Slither → normalized Slither findings → same report ecosystem
```

## Slide 4 — Eleven scoped detectors cover common failure modes

1. Reentrancy
2. `tx.origin` authorization
3. Unchecked low-level calls
4. Unprotected ownership initialization
5. Denial of service
6. Predictable randomness
7. Timestamp dependence
8. Legacy arithmetic overflow/underflow
9. Front-running
10. Short-address ambiguity
11. Uninitialized storage references

## Slide 5 — Evaluation reaches 98.5% recall inside claimed scope

| Metric | Result |
| --- | ---: |
| Labeled contracts | 143 |
| Contracts inside claimed scope | 131 |
| Correctly detected scoped contracts | 129 |
| Scoped recall | 98.5% |
| Automated tests | 37/37 passing |
| Slither verification | 7 normalized findings on `etherstore.sol` |

**Important:** Two reentrancy cases require deeper modifier or cross-function
analysis. Do not describe 98.5% as universal vulnerability accuracy.

## Slide 6 — One upload produces evidence, attack path, and remediation

Live demo:

1. Run `npm run dev`.
2. Upload `Contracts/dataset/reentrancy/etherstore.sol`.
3. Show the compiler version selected from `pragma solidity ^0.4.10`.
4. Show the reentrancy evidence at the external call and later state update.
5. Explain checks-effects-interactions.
6. Download the HTML report.

Optional Slither proof:

```powershell
solc-select use 0.4.26
npm run scan:slither -- .\Contracts\dataset\reentrancy\etherstore.sol .\reports\slither-report.json
```

## Slide 7 — The trust model is explicit

- A clean report does not prove safety.
- Rules are pattern-based and intentionally scoped.
- Compiler success is separate from security success.
- Template explanations are the default.
- External AI is optional and receives only an already-verified finding.
- Slither is optional and retains provenance in normalized output.

## Slide 8 — AegisAI is a usable prototype, not an audit replacement

**Close with:** “The contribution is an evidence-grounded workflow that makes
smart-contract findings easier to verify and act on. The prototype is usable
today, evaluated reproducibly, and designed so deeper analyzers can be added
without weakening its trust model.”

## Short answers for questions

**Where is the AI?**  
The explanation adapter can call an external model, but the security signal
always comes from deterministic rules or Slither. The default is reviewed
templates, preventing hallucinated findings.

**Why not claim 100% accuracy?**  
The dataset covers labeled examples, and the scanner intentionally supports a
defined scope. Two advanced reentrancy cases remain outside the local rule
engine.

**How is this different from Slither?**  
Slither supplies deep static analysis. AegisAI adds pragma-aware upload,
normalized evidence, beginner-readable attack explanations, remediation, UI,
and exportable reports. It can also normalize Slither results.

