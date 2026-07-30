export const RULES = Object.freeze([
  { id: "AEGIS-REENTRANCY-001", title: "External call before state update", severity: "high", confidence: 0.88 },
  { id: "AEGIS-AUTH-001", title: "tx.origin used for authorization", severity: "high", confidence: 0.99 },
  { id: "AEGIS-CALL-001", title: "Unchecked low-level call", severity: "medium", confidence: 0.92 },
  { id: "AEGIS-ACCESS-002", title: "Unprotected ownership initializer", severity: "high", confidence: 0.9 },
  { id: "AEGIS-DOS-001", title: "Operation can be permanently blocked", severity: "high", confidence: 0.87 },
  { id: "AEGIS-RANDOM-001", title: "Predictable on-chain randomness", severity: "high", confidence: 0.93 },
  { id: "AEGIS-TIME-001", title: "Miner-influenced timestamp controls sensitive logic", severity: "medium", confidence: 0.86 },
  { id: "AEGIS-ARITH-001", title: "Unchecked legacy arithmetic", severity: "high", confidence: 0.84 },
  { id: "AEGIS-FRONT-001", title: "Transaction-order dependence", severity: "high", confidence: 0.82 },
  { id: "AEGIS-ABI-001", title: "Short-address ABI ambiguity", severity: "medium", confidence: 0.8 },
  { id: "AEGIS-STORAGE-001", title: "Uninitialized storage reference", severity: "high", confidence: 0.95 },
  { id: "AEGIS-LIFECYCLE-001", title: "Unprotected contract destruction", severity: "high", confidence: 0.96 },
  { id: "AEGIS-DELEGATE-001", title: "User-controlled delegatecall", severity: "high", confidence: 0.94 },
  { id: "AEGIS-HASH-001", title: "Ambiguous packed encoding of dynamic inputs", severity: "medium", confidence: 0.9 }
]);

function lineRecord(lines, index) {
  return { number: index + 1, text: lines[index].trim() };
}

function stripComments(source) {
  let inBlock = false;
  return String(source).split(/\r?\n/).map((line) => {
    let output = "";
    for (let index = 0; index < line.length; index += 1) {
      const current = line[index];
      const next = line[index + 1];
      if (!inBlock && current === "/" && next === "*") {
        inBlock = true;
        index += 1;
      } else if (inBlock && current === "*" && next === "/") {
        inBlock = false;
        index += 1;
      } else if (!inBlock && current === "/" && next === "/") {
        break;
      } else if (!inBlock) {
        output += current;
      }
    }
    return output;
  });
}

function findFunctionRanges(lines) {
  const ranges = [];
  let active = null;
  let depth = 0;
  lines.forEach((line, index) => {
    if (!active && /\bfunction\b/.test(line)) {
      active = { start: index, end: index, bodyStarted: false };
      depth = 0;
    }
    if (!active) return;
    const opens = (line.match(/{/g) || []).length;
    const closes = (line.match(/}/g) || []).length;
    if (opens) active.bodyStarted = true;
    depth += opens - closes;
    active.end = index;
    if (active.bodyStarted && depth <= 0) {
      ranges.push(active);
      active = null;
    }
  });
  if (active) ranges.push(active);
  return ranges;
}

function finding(rule, evidence, details) {
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    confidence: rule.confidence,
    evidence,
    ...details
  };
}

function detectTxOrigin(lines, cleanLines) {
  const rule = RULES[1];
  return cleanLines.flatMap((line, index) => {
    if (!/\btx\.origin\b/.test(line)) return [];
    return [finding(rule, [lineRecord(lines, index)], {
      explanation: "tx.origin identifies the account that began the transaction, not the immediate caller. A malicious intermediary contract can preserve tx.origin while calling this function.",
      attackPath: "An authorized user is tricked into calling an attacker contract. The attacker forwards the call, and the victim still sees the authorized tx.origin.",
      remediation: "Authorize the immediate caller with msg.sender, preferably through an explicit owner or role-based access-control check.",
      fixedExample: 'require(msg.sender == owner, "not authorized");'
    })];
  });
}

function contractNameBefore(lines, lineIndex) {
  let name = "";
  for (let index = 0; index <= lineIndex; index += 1) {
    const match = lines[index].match(/\bcontract\s+([A-Za-z_]\w*)/);
    if (match) name = match[1];
  }
  return name;
}

function detectOwnershipInitializers(lines, cleanLines) {
  const rule = RULES[3];
  const findings = [];
  for (const range of findFunctionRanges(cleanLines)) {
    const signature = cleanLines.slice(range.start, range.end + 1).join(" ").split("{")[0];
    const nameMatch = signature.match(/\bfunction\s+([A-Za-z_]\w*)\s*\(/);
    if (!nameMatch || /\bconstructor\s*\(/.test(signature)) continue;
    const functionName = nameMatch[1];
    const contractName = contractNameBefore(cleanLines, range.start);
    if (functionName === contractName) continue;
    if (!/\b(public|external)\b/.test(signature)) continue;

    const body = cleanLines.slice(range.start, range.end + 1).join("\n");
    const assignmentOffset = cleanLines
      .slice(range.start, range.end + 1)
      .findIndex((line) => /\b(?:owner|admin|creator)\s*=\s*msg\.sender\b/i.test(line));
    if (assignmentOffset < 0) continue;
    const guarded =
      /\brequire\s*\(\s*(?:owner|admin|creator)\s*==\s*address\s*\(\s*0\s*\)/i.test(body) ||
      /\bif\s*\(\s*(?:owner|admin|creator)\s*!=\s*address\s*\(\s*0\s*\)/i.test(body);
    if (guarded) continue;

    const assignmentLine = range.start + assignmentOffset;
    findings.push(finding(rule, [
      lineRecord(lines, range.start),
      lineRecord(lines, assignmentLine)
    ], {
      explanation: `The public ${functionName} function assigns a privileged address but is not a constructor and has no one-time initialization guard. It remains callable after deployment.`,
      attackPath: "An attacker calls the initializer first or calls it again later, becomes the privileged account, and invokes owner-only withdrawal or administrative functions.",
      remediation: "Use the constructor keyword for deployment-time ownership, or protect an initializer with a one-time initialized flag and strict access control.",
      fixedExample: "constructor() {\n    owner = msg.sender;\n}"
    }));
  }
  return findings;
}

function detectUncheckedCalls(lines, cleanLines) {
  const rule = RULES[2];
  return cleanLines.flatMap((line, index) => {
    const lowLevelCall =
      /\.(?:call|delegatecall|callcode)(?:\.value\s*\([^)]*\))?(?:\.gas\s*\([^)]*\))?\s*(?:\{[^}]*\})?\s*\(/;
    const sendCall = /\.send\s*\(/;
    if (!lowLevelCall.test(line) && !sendCall.test(line)) return [];
    const context = cleanLines.slice(index, Math.min(index + 3, cleanLines.length)).join(" ");
    const capturesResult = /\(\s*bool\s+\w+\s*,/.test(line) || /\b(bool\s+)?(?:success|ok|sent)\s*=/.test(line);
    const checksResult = /\brequire\s*\(\s*(?:success|ok|sent)\b/.test(context) || /if\s*\(\s*!\s*(?:success|ok|sent)\b/.test(context);
    const checksInline = /\b(?:if|require|assert)\s*\([^;]*(?:\.call|\.delegatecall|\.callcode|\.send)\b/.test(line);
    const returnsCall = /\breturn\s+[^;]*(?:\.call|\.delegatecall|\.callcode|\.send)\b/.test(line);
    if ((capturesResult && checksResult) || checksInline || returnsCall) return [];
    return [finding(rule, [lineRecord(lines, index)], {
      explanation: "Low-level call returns a success flag instead of reverting automatically. Ignoring it can allow execution to continue after a failed transfer or external operation.",
      attackPath: "The recipient rejects the call or consumes available gas. The contract records completion even though the external action failed.",
      remediation: "Capture the returned success flag and revert when it is false. Consider a safer typed interface when one is available.",
      fixedExample: '(bool success, ) = recipient.call{value: amount}("");\nrequire(success, "call failed");'
    })];
  });
}

function detectReentrancy(lines, cleanLines) {
  const rule = RULES[0];
  const updatePattern =
    /\b\w*(?:balance|credit|deposit|share|amount|holder)\w*\s*\[[^\]]+\]\s*(?:=|-=|\+=)|\b[\w.[\]]*(?:balance|credit|deposit|share|amount)\w*\s*(?:=|-=|\+=)|\bdelete\s+\w+/i;
  const callPattern =
    /\.call\s*\{\s*value\s*:|\.call\.value\s*\(|\.send\s*\(|\.transfer\s*\(/;
  const findings = [];
  for (const range of findFunctionRanges(cleanLines)) {
    let call = -1;
    let update = -1;
    for (let index = range.start; index <= range.end; index += 1) {
      if (call < 0 && callPattern.test(cleanLines[index])) call = index;
      else if (call >= 0 && updatePattern.test(cleanLines[index])) {
        update = index;
        break;
      }
    }
    if (call >= 0 && update > call) {
      findings.push(finding(rule, [lineRecord(lines, call), lineRecord(lines, update)], {
        explanation: "The function transfers control to an external address before updating accounting state. The recipient may call back while the old balance is still available.",
        attackPath: "A malicious recipient re-enters during the external call and repeats the withdrawal before its balance is reduced.",
        remediation: "Apply checks-effects-interactions: validate first, update state second, and perform the external call last. A reentrancy guard can provide defense in depth.",
        fixedExample: 'uint256 amount = balances[msg.sender];\nbalances[msg.sender] = 0;\n(bool success, ) = msg.sender.call{value: amount}("");\nrequire(success, "transfer failed");'
      }));
    }
  }
  return findings;
}

function detectDenialOfService(lines, cleanLines) {
  const rule = RULES[4];
  const findings = [];

  cleanLines.forEach((line, index) => {
    const blockingExternalCall =
      /\b(?:require|assert)\s*\([^;]*(?:\.send\s*\(|\.call(?:\.value)?\s*\()/;
    if (blockingExternalCall.test(line)) {
      findings.push(finding(rule, [lineRecord(lines, index)], {
        explanation: "Progress depends on an external recipient accepting a call. A recipient that always reverts can force the entire operation to fail indefinitely.",
        attackPath: "An attacker becomes a refund or payout recipient and deploys a fallback function that rejects payment. Every later action that must pay that address reverts.",
        remediation: "Do not push payments inside a required state transition. Record each recipient's credit and let recipients withdraw independently.",
        fixedExample: "pendingWithdrawals[recipient] += amount;\n// recipient later calls withdraw()"
      }));
    }

    if (/\b\w+\s*=\s*new\s+\w+\s*\[\s*\]\s*\(\s*0\s*\)/.test(line)) {
      findings.push(finding(rule, [lineRecord(lines, index)], {
        explanation: "This transaction attempts to clear a storage-backed collection in one operation. For a sufficiently large collection, execution can exceed the block gas limit and make the transition unreachable.",
        attackPath: "An attacker or normal usage grows the collection until the cleanup transaction can no longer fit within the available gas limit.",
        remediation: "Use bounded batches, a cursor, or a new logical epoch instead of processing or clearing an arbitrarily large collection at once.",
        fixedExample: "function clearBatch(uint256 limit) external {\n    // process at most limit entries and persist a cursor\n}"
      }));
    }
  });

  for (const range of findFunctionRanges(cleanLines)) {
    for (let index = range.start; index <= range.end; index += 1) {
      const loop = cleanLines[index].match(
        /\bfor\s*\([^;]*;[^;]*<\s*([^;]+);[^)]*\)/
      );
      if (!loop) continue;
      const bound = loop[1].trim();
      const numericBound = Number(bound.match(/^\d+$/)?.[0] || 0);
      const potentiallyUnbounded =
        /\.length\b/.test(bound) ||
        /^[A-Za-z_]\w*$/.test(bound) ||
        numericBound >= 100;
      if (!potentiallyUnbounded) continue;

      const hazardIndex = cleanLines
        .slice(index, range.end + 1)
        .findIndex((candidate) =>
          /\.push\s*\(|\[[^\]]+\]\s*(?:=|\+=|-=)|\.(?:send|transfer)\s*\(|\.call(?:\.value)?\s*\(/.test(candidate)
        );
      if (hazardIndex < 0) continue;
      const operationLine = index + hazardIndex;
      findings.push(finding(rule, [
        lineRecord(lines, index),
        ...(operationLine === index ? [] : [lineRecord(lines, operationLine)])
      ], {
        explanation: `The loop bound (${bound}) can require too much work in one transaction while repeatedly touching storage or external addresses. Execution may eventually exceed the block gas limit.`,
        attackPath: "The collection or caller-controlled iteration count grows until this function always runs out of gas, blocking cleanup, refunds, or other required progress.",
        remediation: "Cap the number of iterations per transaction and persist progress between calls. Prefer pull payments when the loop contacts recipients.",
        fixedExample: "uint256 end = min(cursor + MAX_BATCH, items.length);\nfor (uint256 i = cursor; i < end; i++) { /* bounded work */ }\ncursor = end;"
      }));
    }
  }

  return findings;
}

function detectPredictableRandomness(lines, cleanLines) {
  const rule = RULES[5];
  return cleanLines.flatMap((line, index) => {
    const strongEntropy =
      /\b(?:blockhash\s*\(|block\.blockhash\s*\(|block\.(?:difficulty|prevrandao|coinbase)\b)/;
    const weakModulo =
      /\b(?:block\.number|block\.timestamp|now)\b[^;]*(?:%|keccak256?\s*\()|(?:%|keccak256?\s*\()[^;]*\b(?:block\.number|block\.timestamp|now)\b/;
    if (!strongEntropy.test(line) && !weakModulo.test(line)) return [];
    return [finding(rule, [lineRecord(lines, index)], {
      explanation: "The contract uses miner- or validator-influenced block data as entropy. This data is public before execution and can often be predicted, selected, or withheld by transaction participants or block producers.",
      attackPath: "An attacker calculates the same outcome before submitting a transaction, or a block producer influences the chosen block value, then participates only when the result is profitable.",
      remediation: "Use verifiable randomness such as a VRF, or a carefully designed commit-reveal protocol with deadlines and penalties. Do not use block metadata as the sole entropy source for valuable outcomes.",
      fixedExample: "// Request randomness from a verifiable randomness oracle.\n// Settle the outcome only after the proof is verified."
    })];
  });
}

function detectTimestampDependence(lines, cleanLines) {
  const rule = RULES[6];
  return cleanLines.flatMap((line, index) => {
    if (!/\b(?:block\.timestamp|now)\b/.test(line)) return [];
    const timestampAssignment =
      /\b\w*(?:time|timestamp)\w*\s*=\s*(?:block\.timestamp|now)\b/i.test(line);
    const timestampOutcome =
      /\b(?:block\.timestamp|now)\b[^;]*(?:%|sha3\s*\(|keccak256?\s*\(|\b\d+\s*(?:seconds?|minutes?|hours?|days?|weeks?)\b)/i.test(line);
    const directReturn =
      /\breturn\b[^;]*\b(?:block\.timestamp|now)\b/.test(line);
    if (!timestampAssignment && !timestampOutcome && !directReturn) return [];
    return [finding(rule, [lineRecord(lines, index)], {
      explanation: "This sensitive state or outcome depends directly on the block timestamp. Validators have limited freedom to choose timestamps, so logic near a boundary or using timestamp-derived randomness can be influenced.",
      attackPath: "A validator chooses an allowed timestamp that moves execution across the winning, payout, or state-transition boundary and includes the transaction only when favorable.",
      remediation: "Avoid timestamp-derived randomness. For deadlines, tolerate timestamp drift and do not rely on exact equality or very short windows; use a VRF or commit-reveal scheme for outcomes.",
      fixedExample: "require(block.timestamp >= deadline, \"too early\");\n// Use a sufficiently large safety window; never derive randomness from time."
    })];
  });
}

function detectLegacyArithmetic(lines, cleanLines, source) {
  const rule = RULES[7];
  const pragma = String(source).match(/pragma\s+solidity\s+([^;]+);/i)?.[1] || "";
  if (/\b0\.[89]\.|\b[1-9]\d*\.\d+\./.test(pragma)) return [];
  return cleanLines.flatMap((line, index) => {
    if (/\bSafeMath\b|\.(?:add|sub|mul|div)\s*\(/.test(line)) return [];
    const compound = /\b[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|\*=)\s*[^;]+;/;
    const computedAssignment =
      /(?:\b(?:u?int\d*|var)\s+)?[A-Za-z_]\w*\s*=\s*[^;]*(?:\+|-|\*)[^;]+;/;
    const suspiciousGuard = /\brequire\s*\([^;]*\b\w+\s*-\s*\w+\s*>=\s*0\s*\)/;
    if (!compound.test(line) && !computedAssignment.test(line) && !suspiciousGuard.test(line)) return [];
    return [finding(rule, [lineRecord(lines, index)], {
      explanation: "Arithmetic in Solidity versions before 0.8 wraps on overflow or underflow unless the contract performs an explicit bound check or uses a checked-math library.",
      attackPath: "An attacker supplies a value that wraps the result around the integer range, creating an unexpectedly large balance, bypassing a limit, or reducing accounting to an invalid value.",
      remediation: "Use Solidity 0.8 or newer, or apply a reviewed checked-arithmetic library and validate operands before every legacy arithmetic operation.",
      fixedExample: "require(value <= type(uint256).max - balance, \"overflow\");\nbalance += value;"
    })];
  });
}

function detectTransactionOrderDependence(lines, cleanLines) {
  const rule = RULES[8];
  const findings = [];
  for (const range of findFunctionRanges(cleanLines)) {
    const bodyLines = cleanLines.slice(range.start, range.end + 1);
    const body = bodyLines.join("\n");
    const signature = bodyLines.join(" ").split("{")[0];
    let evidenceOffset = -1;
    let explanation = "";
    if (
      /\bfunction\s+approve\s*\(/.test(signature) &&
      /\b(?:allowed|allowance|_allowed)\b[\s\S]*=\s*\w+/.test(body)
    ) {
      evidenceOffset = 0;
      explanation = "Changing an existing token allowance directly creates an ordering race: the spender can consume the old allowance before the replacement transaction executes.";
    } else if (
      /\b(?:solution|answer|secret|number)\b/i.test(signature) &&
      /\b(?:sha3|keccak256)\s*\(/.test(body) &&
      /\.(?:transfer|send)\s*\(/.test(body)
    ) {
      evidenceOffset = bodyLines.findIndex((line) => /\b(?:sha3|keccak256)\s*\(/.test(line));
      explanation = "A profitable solution is revealed in the public transaction input. Another participant can copy it from the mempool and submit a transaction with higher priority.";
    } else if (
      /\bfunction\s+(?:play|claim|setReward)\s*\(/.test(signature) &&
      (/\bplayers?\s*\[[^\]]+\]\s*=/.test(body) ||
        /\.(?:transfer|send)\s*\([^)]*reward/.test(body))
    ) {
      evidenceOffset = bodyLines.findIndex((line) =>
        /\bplayers?\s*\[[^\]]+\]\s*=|\.(?:transfer|send)\s*\([^)]*reward/.test(line)
      );
      explanation = "The result depends on which public transaction is ordered first. A mempool observer can copy or outbid the pending transaction and capture the reward or favorable position.";
    }
    if (evidenceOffset < 0) continue;
    findings.push(finding(rule, [
      lineRecord(lines, range.start),
      ...(evidenceOffset ? [lineRecord(lines, range.start + evidenceOffset)] : [])
    ], {
      explanation,
      attackPath: "An attacker monitors pending transactions, submits a competing transaction with higher priority, and changes who receives the reward or which state update is applied first.",
      remediation: "Use commit-reveal for secrets, allowance increase/decrease methods or zero-first approval, and bind rewards to a precommitted participant rather than transaction ordering.",
      fixedExample: "bytes32 commitment = keccak256(abi.encodePacked(secret, msg.sender, salt));\n// reveal the secret in a later transaction"
    }));
  }
  return findings;
}

function detectShortAddressRisk(lines, cleanLines) {
  const rule = RULES[9];
  const findings = [];
  for (const range of findFunctionRanges(cleanLines)) {
    const joined = cleanLines.slice(range.start, range.end + 1).join(" ");
    const functionStart = joined.indexOf("function");
    const signature = joined.slice(functionStart >= 0 ? functionStart : 0).split("{")[0];
    if (!/\bfunction\s+\w+\s*\(\s*address\s+\w+\s*,\s*uint(?:\d+)?\s+\w+/.test(signature)) continue;
    const body = cleanLines.slice(range.start, range.end + 1).join("\n");
    if (/\bmsg\.data\.length\b/.test(body)) continue;
    findings.push(finding(rule, [lineRecord(lines, range.start)], {
      explanation: "This legacy ABI entry point accepts an address followed by an integer without validating calldata length. Malformed short-address calldata can shift the decoded integer value.",
      attackPath: "A client or exchange submits an address with missing bytes. Legacy ABI decoding pads the payload and interprets the following amount at the wrong offset.",
      remediation: "Use modern Solidity ABI decoding and validate inputs in the client. For legacy contracts, require the exact expected msg.data length before processing.",
      fixedExample: "require(msg.data.length == 4 + 32 + 32, \"invalid calldata length\");"
    }));
  }
  return findings;
}

function detectUninitializedStorage(lines, cleanLines) {
  const rule = RULES[10];
  return cleanLines.flatMap((line, index) => {
    const declaration = line.match(/^\s*([A-Z][A-Za-z_]\w*)\s+([a-zA-Z_]\w*)\s*;\s*$/);
    if (!declaration) return [];
    const nextContext = cleanLines.slice(index + 1, index + 4).join("\n");
    if (!new RegExp(`\\b${declaration[2]}\\s*\\.`).test(nextContext)) return [];
    return [finding(rule, [lineRecord(lines, index)], {
      explanation: "A local reference-type variable is declared without memory or an initialized storage location. In legacy Solidity it can alias storage slot zero and overwrite unrelated contract state.",
      attackPath: "Calling the function writes fields through the uninitialized reference, corrupting ownership, balances, or other state stored in the aliased slot.",
      remediation: "Declare temporary structs or arrays as memory and initialize them, or explicitly reference the intended storage object.",
      fixedExample: `${declaration[1]} memory ${declaration[2]};`
    })];
  });
}

function hasAccessControl(signature, body) {
  return /\b(?:onlyOwner|onlyAdmin|onlyRole|authorized|auth)\b/i.test(signature) ||
    /\brequire\s*\(\s*msg\.sender\s*==\s*(?:owner|admin|administrator)\b/i.test(body) ||
    /\brequire\s*\([^;]*(?:hasRole|isOwner|isAdmin)\s*\(/i.test(body);
}

function detectUnprotectedDestruction(lines, cleanLines) {
  const rule = RULES[11];
  const findings = [];
  for (const range of findFunctionRanges(cleanLines)) {
    const bodyLines = cleanLines.slice(range.start, range.end + 1);
    const body = bodyLines.join("\n");
    const signature = bodyLines.join(" ").split("{")[0];
    if (/\b(?:private|internal)\b/.test(signature)) continue;
    if (!/\b(?:public|external)\b/.test(signature)) continue;
    const callOffset = bodyLines.findIndex((line) => /\b(?:selfdestruct|suicide)\s*\(/.test(line));
    if (callOffset < 0 || hasAccessControl(signature, body)) continue;
    findings.push(finding(rule, [
      lineRecord(lines, range.start),
      ...(callOffset ? [lineRecord(lines, range.start + callOffset)] : [])
    ], {
      explanation: "A publicly reachable function can execute contract destruction without an owner or role check. Depending on the EVM revision, this can transfer the full balance and may remove code for contracts created in the same transaction.",
      attackPath: "An arbitrary caller invokes the function, redirects or triggers the forced balance transfer, and permanently disrupts the protocol's expected lifecycle.",
      remediation: "Remove contract destruction when possible. If lifecycle termination is essential, restrict it with explicit role-based access control, a delay, and a reviewed recipient.",
      fixedExample: "function shutdown(address payable recipient) external onlyOwner {\n    selfdestruct(recipient);\n}"
    }));
  }
  return findings;
}

function dynamicParameterNames(signature) {
  const names = [];
  const pattern = /\b(?:string|bytes(?!\d)|[A-Za-z_]\w*\s*\[\s*\])\s*(?:calldata|memory|storage)?\s+([A-Za-z_]\w*)/g;
  for (const match of signature.matchAll(pattern)) names.push(match[1]);
  return names;
}

function addressParameterNames(signature) {
  return [...signature.matchAll(/\baddress(?:\s+payable)?\s+([A-Za-z_]\w*)/g)]
    .map((match) => match[1]);
}

function detectUserControlledDelegatecall(lines, cleanLines) {
  const rule = RULES[12];
  const findings = [];
  for (const range of findFunctionRanges(cleanLines)) {
    const bodyLines = cleanLines.slice(range.start, range.end + 1);
    const body = bodyLines.join("\n");
    const signature = bodyLines.join(" ").split("{")[0];
    if (!/\b(?:public|external)\b/.test(signature) || hasAccessControl(signature, body)) continue;
    for (const parameter of addressParameterNames(signature)) {
      const callOffset = bodyLines.findIndex((line) =>
        new RegExp(`\\b${parameter}\\s*\\.\\s*delegatecall\\s*\\(`).test(line)
      );
      if (callOffset < 0) continue;
      const validated =
        new RegExp(`\\brequire\\s*\\([^;]*(?:${parameter}\\s*==|allowed\\s*\\[\\s*${parameter}\\s*\\]|trusted\\s*\\[\\s*${parameter}\\s*\\])`).test(body);
      if (validated) continue;
      findings.push(finding(rule, [
        lineRecord(lines, range.start),
        ...(callOffset ? [lineRecord(lines, range.start + callOffset)] : [])
      ], {
        explanation: `The public function delegates execution to the caller-supplied ${parameter} address. Delegatecall runs foreign code in this contract's storage and authority context.`,
        attackPath: "An attacker supplies a malicious implementation that overwrites ownership or critical storage, transfers assets, or permanently corrupts the contract.",
        remediation: "Delegate only to a fixed or governance-approved implementation. Validate the target against an allowlist and protect upgrade paths with strong access control and a delay.",
        fixedExample: "require(approvedImplementations[target], \"untrusted implementation\");\n(bool ok, ) = target.delegatecall(data);\nrequire(ok, \"delegatecall failed\");"
      }));
      break;
    }
  }
  return findings;
}

function detectPackedEncodingCollision(lines, cleanLines) {
  const rule = RULES[13];
  const findings = [];
  for (const range of findFunctionRanges(cleanLines)) {
    const bodyLines = cleanLines.slice(range.start, range.end + 1);
    const signature = bodyLines.join(" ").split("{")[0];
    const dynamicNames = dynamicParameterNames(signature);
    if (dynamicNames.length < 2) continue;
    const hashOffset = bodyLines.findIndex((line) =>
      /\b(?:keccak256|sha3)\s*\(\s*abi\.encodePacked\s*\(/.test(line) &&
      dynamicNames.filter((name) => new RegExp(`\\b${name}\\b`).test(line)).length >= 2
    );
    if (hashOffset < 0) continue;
    findings.push(finding(rule, [
      lineRecord(lines, range.start),
      ...(hashOffset ? [lineRecord(lines, range.start + hashOffset)] : [])
    ], {
      explanation: "abi.encodePacked removes length boundaries between multiple dynamic values. Different input pairs can therefore produce the same byte sequence and the same hash.",
      attackPath: "An attacker chooses alternate dynamic inputs whose packed concatenation matches an authorized message, commitment, or signature digest.",
      remediation: "Use abi.encode for hashing multiple dynamic values, or include unambiguous length/type separators before hashing.",
      fixedExample: "bytes32 digest = keccak256(abi.encode(firstValue, secondValue));"
    }));
  }
  return findings;
}

export function scanSolidity(source) {
  const startedAt = performance.now();
  const lines = String(source || "").split(/\r?\n/);
  const cleanLines = stripComments(source);
  const findings = [
    ...detectReentrancy(lines, cleanLines),
    ...detectTxOrigin(lines, cleanLines),
    ...detectOwnershipInitializers(lines, cleanLines),
    ...detectUncheckedCalls(lines, cleanLines),
    ...detectDenialOfService(lines, cleanLines),
    ...detectPredictableRandomness(lines, cleanLines),
    ...detectTimestampDependence(lines, cleanLines),
    ...detectLegacyArithmetic(lines, cleanLines, source),
    ...detectTransactionOrderDependence(lines, cleanLines),
    ...detectShortAddressRisk(lines, cleanLines),
    ...detectUninitializedStorage(lines, cleanLines),
    ...detectUnprotectedDestruction(lines, cleanLines),
    ...detectUserControlledDelegatecall(lines, cleanLines),
    ...detectPackedEncodingCollision(lines, cleanLines)
  ].sort((a, b) => {
    const rank = { high: 3, medium: 2, low: 1 };
    return rank[b.severity] - rank[a.severity] || a.evidence[0].number - b.evidence[0].number;
  });
  const counts = findings.reduce((result, item) => {
    result[item.severity] += 1;
    return result;
  }, { high: 0, medium: 0, low: 0 });
  return {
    schemaVersion: "1.0",
    scanner: "AegisAI deterministic prototype",
    scannedAt: new Date().toISOString(),
    durationMs: Number((performance.now() - startedAt).toFixed(2)),
    lineCount: lines.length,
    counts,
    findings,
    limitations: [
      "Pattern-based analysis does not prove that a contract is safe.",
      "Cross-file data flow, inheritance, assembly, and proxy behavior are not analyzed.",
      "Explanation text is reviewed template guidance, not an independent AI security claim."
    ]
  };
}
