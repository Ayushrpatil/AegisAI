import test from "node:test";
import assert from "node:assert/strict";
import { analyzeContract } from "../server/analyze.js";
import { fixedSample, vulnerableSample } from "../src/samples.js";

test("compiles and scans a real vulnerable Solidity source file", () => {
  const report = analyzeContract(vulnerableSample, "VulnerableVault.sol");
  assert.equal(report.sourceName, "VulnerableVault.sol");
  assert.equal(report.compiler.available, true);
  assert.equal(report.compiler.compiled, true);
  assert.match(report.engine, /^solc /);
  assert.equal(report.findings.length, 3);
});

test("returns genuine compiler diagnostics for invalid Solidity", () => {
  const report = analyzeContract("pragma solidity ^0.8.20; contract Broken {", "Broken.sol");
  assert.equal(report.compiler.compiled, false);
  assert.ok(report.compiler.diagnostics.some((item) => item.severity === "error"));
});

test("compiles the corrected source without supported findings", () => {
  const report = analyzeContract(fixedSample, "SaferVault.sol");
  assert.equal(report.compiler.compiled, true);
  assert.equal(report.findings.length, 0);
});

test("selects Solidity 0.4.26 for a legacy 0.4 source file", () => {
  const source = `
    pragma solidity ^0.4.15;
    contract Auction {
      function Auction() public {}
      function() public payable {}
    }
  `;
  const report = analyzeContract(source, "auction.sol");
  assert.equal(report.compiler.compiled, true);
  assert.match(report.compiler.version, /^0\.4\.26/);
  assert.equal(report.compiler.requestedPragma, "^0.4.15");
});

test("compiles and flags a misnamed legacy constructor", () => {
  const source = `
    pragma solidity ^0.4.24;
    contract Missing {
      address private owner;
      function IamMissing() public { owner = msg.sender; }
    }
  `;
  const report = analyzeContract(source, "incorrect_constructor.sol");
  assert.equal(report.compiler.compiled, true);
  assert.match(report.compiler.version, /^0\.4\.26/);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-ACCESS-002"));
});

test("honors an exact Solidity 0.4.24 pragma", () => {
  const source = `
    pragma solidity 0.4.24;
    contract SendLoop {
      function refund(address recipient) public {
        recipient.send(1);
      }
    }
  `;
  const report = analyzeContract(source, "send_loop.sol");
  assert.equal(report.compiler.compiled, true);
  assert.match(report.compiler.version, /^0\.4\.26/);
  assert.equal(report.compiler.requestedPragma, "0.4.24");
  assert.equal(report.compiler.pragmaNormalized, true);
});

test("honors an exact Solidity 0.4.25 pragma", () => {
  const report = analyzeContract(
    "pragma solidity 0.4.25; contract ExactVersion {}",
    "exact_version.sol"
  );
  assert.equal(report.compiler.compiled, true);
  assert.match(report.compiler.version, /^0\.4\.26/);
  assert.equal(report.compiler.pragmaNormalized, true);
});

test("selects a compatible compiler for Solidity 0.5 sources", () => {
  const report = analyzeContract(
    "pragma solidity ^0.5.0; contract VersionFive {}",
    "version_five.sol"
  );
  assert.equal(report.compiler.compiled, true);
  assert.match(report.compiler.version, /^0\.5\.17/);
});

test("selects a compatible compiler for Solidity 0.6 sources", () => {
  const report = analyzeContract(
    "pragma solidity ^0.6.0; contract VersionSix {}",
    "version_six.sol"
  );
  assert.equal(report.compiler.compiled, true);
  assert.match(report.compiler.version, /^0\.6\.12/);
});

test("selects a compatible compiler for Solidity 0.7 sources", () => {
  const report = analyzeContract(
    "pragma solidity ^0.7.0; contract VersionSeven {}",
    "version_seven.sol"
  );
  assert.equal(report.compiler.compiled, true);
  assert.match(report.compiler.version, /^0\.7\.6/);
});
