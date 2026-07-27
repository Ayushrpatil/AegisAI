import test from "node:test";
import assert from "node:assert/strict";
import { scanSolidity } from "../src/scanner.js";
import { fixedSample, vulnerableSample } from "../src/samples.js";

test("detects all three supported patterns in the vulnerable sample", () => {
  const report = scanSolidity(vulnerableSample);
  const rules = report.findings.map((item) => item.ruleId);
  assert.equal(report.findings.length, 3);
  assert.ok(rules.includes("AEGIS-REENTRANCY-001"));
  assert.ok(rules.includes("AEGIS-AUTH-001"));
  assert.ok(rules.includes("AEGIS-CALL-001"));
  assert.equal(report.counts.high, 2);
  assert.equal(report.counts.medium, 1);
});

test("reports no supported patterns for the corrected sample", () => {
  const report = scanSolidity(fixedSample);
  assert.equal(report.findings.length, 0);
  assert.deepEqual(report.counts, { high: 0, medium: 0, low: 0 });
});

test("ignores vulnerability terms inside comments", () => {
  const report = scanSolidity(`contract CommentOnly {
    // require(tx.origin == owner);
    /* recipient.call(""); */
  }`);
  assert.equal(report.findings.length, 0);
});

test("includes evidence and remediation for every finding", () => {
  for (const item of scanSolidity(vulnerableSample).findings) {
    assert.ok(item.evidence.every((line) => line.number > 0 && line.text));
    assert.ok(item.explanation && item.attackPath && item.remediation && item.fixedExample);
  }
});

test("detects legacy call.value reentrancy used by labeled datasets", () => {
  const report = scanSolidity(`contract LegacyBank {
    mapping(address => uint) userBalances;
    function withdraw() public {
      uint amount = userBalances[msg.sender];
      if (!(msg.sender.call.value(amount)())) { throw; }
      userBalances[msg.sender] = 0;
    }
  }`);
  assert.ok(report.findings.some((item) => item.ruleId === "AEGIS-REENTRANCY-001"));
});

test("detects legacy unchecked call.value gas chains and send", () => {
  const report = scanSolidity(`contract LegacyCalls {
    function pay(address target, uint amount) public {
      target.call.value(amount).gas(800000)();
      target.send(amount);
    }
  }`);
  assert.equal(
    report.findings.filter((item) => item.ruleId === "AEGIS-CALL-001").length,
    2
  );
});

test("detects a misnamed legacy constructor that can replace the owner", () => {
  const report = scanSolidity(`pragma solidity ^0.4.24;
  contract Missing {
    address private owner;
    function IamMissing() public {
      owner = msg.sender;
    }
    function withdraw() public {
      owner.transfer(this.balance);
    }
  }`);
  const item = report.findings.find((finding) => finding.ruleId === "AEGIS-ACCESS-002");
  assert.ok(item);
  assert.equal(item.severity, "high");
  assert.match(item.explanation, /not a constructor/);
});

test("does not flag a correctly named legacy constructor or modern constructor", () => {
  const legacy = scanSolidity(`pragma solidity ^0.4.21;
  contract Wallet {
    address owner;
    function Wallet() public { owner = msg.sender; }
  }`);
  const modern = scanSolidity(`pragma solidity ^0.8.20;
  contract Wallet {
    address owner;
    constructor() { owner = msg.sender; }
  }`);
  assert.ok(!legacy.findings.some((finding) => finding.ruleId === "AEGIS-ACCESS-002"));
  assert.ok(!modern.findings.some((finding) => finding.ruleId === "AEGIS-ACCESS-002"));
});

test("detects a required refund that lets a recipient block an auction", () => {
  const report = scanSolidity(`contract Auction {
    address currentFrontrunner;
    uint currentBid;
    function bid() public payable {
      require(currentFrontrunner.send(currentBid));
      currentFrontrunner = msg.sender;
    }
  }`);
  const item = report.findings.find((finding) => finding.ruleId === "AEGIS-DOS-001");
  assert.ok(item);
  assert.match(item.explanation, /recipient/);
});

test("detects gas denial of service from an unbounded payout loop", () => {
  const report = scanSolidity(`contract Refunder {
    address[] recipients;
    mapping(address => uint) refunds;
    function refundAll() public {
      for (uint i = 0; i < recipients.length; i++) {
        require(recipients[i].send(refunds[recipients[i]]));
      }
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-DOS-001"));
});

test("detects a large storage-writing loop", () => {
  const report = scanSolidity(`contract Collector {
    address[] creditors;
    function addMany() public {
      for (uint i = 0; i < 350; i++) {
        creditors.push(msg.sender);
      }
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-DOS-001"));
});

test("does not flag a small bounded memory-only loop", () => {
  const report = scanSolidity(`contract Calculator {
    function sum(uint[4] memory values) public pure returns (uint total) {
      for (uint i = 0; i < 4; i++) {
        total += values[i];
      }
    }
  }`);
  assert.ok(!report.findings.some((finding) => finding.ruleId === "AEGIS-DOS-001"));
});

test("detects a lottery outcome derived from block number", () => {
  const report = scanSolidity(`contract Lottery {
    function draw() public view returns (bool) {
      return block.number % 2 == 0;
    }
  }`);
  const item = report.findings.find((finding) => finding.ruleId === "AEGIS-RANDOM-001");
  assert.ok(item);
  assert.match(item.remediation, /VRF|commit-reveal/);
});

test("detects blockhash used as an entropy source", () => {
  const report = scanSolidity(`contract GuessingGame {
    function answer() public view returns (bytes32) {
      return blockhash(block.number - 1);
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-RANDOM-001"));
});

test("detects validator-influenced difficulty and coinbase", () => {
  const report = scanSolidity(`contract Raffle {
    function seed() public view returns (bytes32) {
      return keccak256(abi.encodePacked(block.prevrandao, block.coinbase));
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-RANDOM-001"));
});

test("does not treat an ordinary timestamp deadline as randomness", () => {
  const report = scanSolidity(`contract Timelock {
    uint public unlockTime;
    function withdraw() public view {
      require(block.timestamp >= unlockTime, "locked");
    }
  }`);
  assert.ok(!report.findings.some((finding) => finding.ruleId === "AEGIS-RANDOM-001"));
});

test("detects timestamp-derived lottery outcomes", () => {
  const report = scanSolidity(`contract Lotto {
    function play() public view returns (uint) {
      return uint(keccak256(abi.encodePacked(block.timestamp))) % 2;
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-TIME-001"));
});

test("detects a timestamp saved for a short payout window", () => {
  const report = scanSolidity(`contract Jackpot {
    uint lastInvestmentTimestamp;
    function invest() public payable {
      lastInvestmentTimestamp = block.timestamp;
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-TIME-001"));
});

test("detects timestamp returned as pseudo-random input", () => {
  const report = scanSolidity(`contract Draw {
    function randomGen() public view returns (uint) {
      return block.timestamp;
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-TIME-001"));
});

test("does not flag a long ordinary deadline guard", () => {
  const report = scanSolidity(`contract Timelock {
    uint public unlockTime;
    function withdraw() public view {
      require(block.timestamp >= unlockTime, "locked");
    }
  }`);
  assert.ok(!report.findings.some((finding) => finding.ruleId === "AEGIS-TIME-001"));
});

test("detects unchecked arithmetic in legacy Solidity", () => {
  const report = scanSolidity(`pragma solidity ^0.4.24;
  contract Token {
    mapping(address => uint) balances;
    function credit(uint value) public { balances[msg.sender] += value; }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-ARITH-001"));
});

test("does not flag native checked arithmetic in Solidity 0.8", () => {
  const report = scanSolidity(`pragma solidity ^0.8.20;
  contract Counter { uint count; function add(uint value) public { count += value; } }`);
  assert.ok(!report.findings.some((finding) => finding.ruleId === "AEGIS-ARITH-001"));
});

test("detects a public hash solution that can be copied from the mempool", () => {
  const report = scanSolidity(`contract Puzzle {
    bytes32 hash;
    function solve(string solution) public {
      require(hash == keccak256(bytes(solution)));
      msg.sender.transfer(1 ether);
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-FRONT-001"));
});

test("detects direct ERC20 allowance replacement", () => {
  const report = scanSolidity(`contract Token {
    mapping(address => mapping(address => uint)) _allowed;
    function approve(address spender, uint value) public returns (bool) {
      _allowed[msg.sender][spender] = value;
      return true;
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-FRONT-001"));
});

test("detects a legacy short-address ABI entry point", () => {
  const report = scanSolidity(`pragma solidity ^0.4.24;
  contract Coin { function sendCoin(address to, uint amount) public returns (bool) { return true; } }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-ABI-001"));
});

test("detects an uninitialized legacy storage reference", () => {
  const report = scanSolidity(`pragma solidity ^0.4.24;
  contract GameStore {
    struct Game { address player; }
    function play() public {
      Game game;
      game.player = msg.sender;
    }
  }`);
  assert.ok(report.findings.some((finding) => finding.ruleId === "AEGIS-STORAGE-001"));
});
