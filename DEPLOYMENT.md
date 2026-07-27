# AegisAI Deployment

## Local verification

```powershell
npm install
npm test
npm run evaluate
npm run build
npm run dev
```

## Vercel deployment

From the folder containing `package.json`:

```powershell
vercel
vercel --prod
```

The repository already defines Vite as the framework, `npm run build` as the
build command, and `dist` as the output directory.

After deployment, verify:

1. The home page loads.
2. A vulnerable sample produces findings.
3. A corrected sample produces no supported findings.
4. A real `.sol` file can be selected.
5. JSON and HTML reports download.
6. `/api/scan` returns a compiler-backed report.

## Optional explanation endpoint

Set `AEGIS_EXPLANATION_ENDPOINT` only when deploying a compatible grounded
explanation service. The scanner remains usable without it.

Do not expose provider secrets through `VITE_` variables because those values
are bundled into browser code.

## Optional Slither

The CLI Slither bridge is intended for a trusted local or controlled server
environment. It is not executed in the browser or required by the Vercel
frontend.

```powershell
solc-select use 0.4.26
npm run scan:slither -- .\Contracts\dataset\reentrancy\etherstore.sol .\reports\slither-report.json
```

## Release checklist

- `npm test` passes.
- `npm run build` passes.
- Dataset report is regenerated.
- No private keys or API secrets are committed.
- The public README states that the prototype is not an audit replacement.
- The deployed UI is tested with at least one vulnerable and one corrected
  contract.

