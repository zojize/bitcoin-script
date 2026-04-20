---
theme: none
title: "Bitcoin Script: Formal Verification with K Framework"
info: |
  Formal semantics for Bitcoin Script using the K Framework.
  Feature-complete pre-Tapscript with full Bitcoin Core test coverage.
class: text-center
transition: fade
drawings:
  persist: false
---

<div class="h-full flex flex-col items-center justify-center">
  <div class="mb-8 font-mono text-sm tracking-widest uppercase op-40">Formal Verification</div>
  <h1 class="!text-5xl !font-bold !leading-tight font-mono !mb-4">
    <span class="text-amber">Bitcoin Script</span><br>
    <span class="op-60 !text-3xl">× K Framework</span>
  </h1>
  <div class="mt-6 font-mono text-sm op-50 space-y-1">
    <div>225,417 mainnet inputs verified</div>
    <div>1,217 / 1,222 Bitcoin Core vectors passing</div>
  </div>
  <div class="mt-12 text-xs op-30 font-mono">Jeff Zou · Lawrence Wang · April 2026</div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> What is Bitcoin Script?</h2>

  <div class="grid grid-cols-2 gap-12">
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">The Language</div>
      <ul class="space-y-3 text-lg">
        <li v-click>Stack-based, Forth-like language</li>
        <li v-click>Every Bitcoin transaction contains scripts</li>
        <li v-click>~100 opcodes: crypto, arithmetic, flow control</li>
        <li v-click>No loops — always terminates</li>
      </ul>
    </div>
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">Why It's Hard to Specify</div>
      <ul class="space-y-3 text-lg">
        <li v-click>Multi-phase execution: scriptSig, scriptPubKey, P2SH redeem, witness</li>
        <li v-click>16 consensus flags with complex interactions</li>
        <li v-click>Subtle encodings: CScriptNum, DER signatures, sighash variants</li>
        <li v-click>Historical consensus bugs that can't be fixed without a chain split</li>
      </ul>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Why Formal Semantics?</h2>

  <div class="grid grid-cols-2 gap-12">
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">The Problem</div>
      <ul class="space-y-3 text-lg">
        <li v-click>Bitcoin Core's C++ is the <em>de facto</em> spec</li>
        <li v-click>Consensus bugs = lost funds, chain splits</li>
        <li v-click>No independent formal specification exists</li>
        <li v-click>Hard to reason about opcode interactions</li>
      </ul>
    </div>
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">K Framework Approach</div>
      <ul class="space-y-3 text-lg">
        <li v-click>Executable formal semantics in K</li>
        <li v-click>Mathematical rigor + runnable interpreter</li>
        <li v-click>Prove properties about scripts</li>
        <li v-click>Zero correctness mismatches on 225K real mainnet inputs</li>
      </ul>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-12">
  <h2 class="!text-3xl font-mono !mb-6"><span class="text-amber">#</span> K Semantics Architecture</h2>

  <div class="grid grid-cols-5 gap-6">
    <div class="col-span-3">

```haskell {maxHeight:'380px'}
configuration
  <T>
    <k> #init </k>
    <stack> .List </stack>
    <altstack> .List </altstack>
    <exec> .List </exec>
    <phase> scriptSig </phase>
    <error> "" </error>
    <sighash> $SIGHASH:Bytes </sighash>
    <scriptSigBytes> $SCRIPTSIG:Bytes </scriptSigBytes>
    <scriptPubKeyBytes> $SCRIPTPUBKEY:Bytes </scriptPubKeyBytes>
    <witness> $WITNESS:Bytes </witness>
    <savedStack> .List </savedStack>
    <opCount> 0 </opCount>
    <flags> $FLAGS:Int </flags>
    <txVersion> $TXVERSION:Int </txVersion>
    <nLockTime> $NLOCKTIME:Int </nLockTime>
    <nSequence> $NSEQUENCE:Int </nSequence>
    <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
    <codesepIdx> 0 </codesepIdx>
  </T>
```

</div>
    <div class="col-span-2 flex flex-col justify-center">
      <div class="font-mono text-xs op-50 mb-4 uppercase tracking-wider">Modules</div>
      <div class="space-y-2 font-mono text-sm">
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-semantics</span> config + phases</div>
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-sig</span> CHECKSIG/MULTISIG</div>
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-crypto</span> DER, sighash, ECDSA</div>
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-flow</span> IF/ELSE, CLTV/CSV</div>
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-decode</span> byte-level decoder</div>
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-arith</span> arithmetic opcodes</div>
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-stack</span> stack manipulation</div>
        <div v-click class="p-2 border border-white/10 rounded"><span class="text-amber">script-num</span> CScriptNum encoding</div>
      </div>
      <div v-click class="mt-4 p-2 border border-amber/30 rounded font-mono text-xs text-amber">
        4 phases: scriptSig → scriptPubKey → p2sh-redeem → witness-v0
      </div>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Implementation Challenges</h2>

  <div class="space-y-6">
    <div v-click class="p-4 border border-white/10 rounded-lg">
      <div class="font-mono text-amber mb-1">Multi-phase execution</div>
      <div class="text-sm op-70">Scripts run across up to 4 chained phases. The stack must be saved before scriptPubKey and restored for P2SH redeem script execution. P2SH-wrapped SegWit requires detecting a witness program inside the redeem script — all modeled as explicit K phase transitions with separate rules for each path.</div>
    </div>
    <div v-click class="p-4 border border-white/10 rounded-lg">
      <div class="font-mono text-amber mb-1">CScriptNum encoding</div>
      <div class="text-sm op-70">Bitcoin integers use sign-magnitude encoding, not two's complement. Getting this wrong causes silent correctness failures on real transactions. Required its own 159-line K module. Correctness is backed by a proven roundtrip lemma used by the Haskell prover backend.</div>
    </div>
    <div v-click class="p-4 border border-white/10 rounded-lg">
      <div class="font-mono text-amber mb-1">Sighash computation in K</div>
      <div class="text-sm op-70">Originally Python pre-computed sighash and passed it as a config variable. The semantics now compute sighash directly in K — legacy, BIP-143 (SegWit v0), and BIP-341/342 (Taproot) tagged hash — enabling true end-to-end verification from raw transaction bytes.</div>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-12">
  <h2 class="!text-3xl font-mono !mb-6"><span class="text-amber">#</span> Formal Proofs</h2>

  <div class="grid grid-cols-5 gap-8">
    <div class="col-span-3">

```haskell {maxHeight:'320px'}
// CScriptNum roundtrip — key lemma for symbolic arithmetic
// Lets the prover reason about OP_ADD/OP_SUB/OP_NEGATE
// for ALL valid inputs, not just concrete test cases
rule scriptNumToInt(intToScriptNum(N)) => N
  requires N >=Int -2147483647
   andBool N <=Int 2147483647
  [simplification]

// Validity preservation under negation
rule validNumFlags(intToScriptNum(0 -Int N), _F) => true
  requires N >=Int -2147483647
   andBool N <=Int 2147483647
  [simplification]
```

</div>
    <div class="col-span-2 flex flex-col justify-center space-y-3">
      <div class="font-mono text-xs op-50 mb-1 uppercase tracking-wider">34 claims proven across 9 spec files</div>
      <div v-click class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">arithmetic</span> · <span class="op-60">OP_ADD, OP_NEGATE for all valid N</span></div>
      <div v-click class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">symbolic</span> · <span class="op-60">OP_EQUAL, OP_NOT, OP_WITHIN</span></div>
      <div v-click class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">timelock / htlc</span> · <span class="op-60">CLTV pass/fail, HTLC expiry paths</span></div>
      <div v-click class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">phase / limits</span> · <span class="op-60">stack passing, CLEANSTACK, SIGPUSHONLY</span></div>
      <div v-click class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">historical-bugs</span> · <span class="op-60">MINIMALDATA, NULLDUMMY before/after flag activation</span></div>
      <div v-click class="mt-2 p-2 border border-amber/30 rounded font-mono text-xs text-amber">
        → Same K definition runs tests and drives the prover
      </div>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Test Coverage</h2>

  <div class="grid grid-cols-3 gap-8 mb-10">
    <div v-click class="text-center p-6 border border-amber/20 rounded-lg">
      <div class="text-4xl font-bold text-amber font-mono">1,217</div>
      <div class="text-sm op-50 mt-2 font-mono">script_tests passing</div>
      <div class="text-xs op-30 mt-1">(5 taproot xfailed)</div>
    </div>
    <div v-click class="text-center p-6 border border-amber/20 rounded-lg">
      <div class="text-4xl font-bold text-amber font-mono">133</div>
      <div class="text-sm op-50 mt-2 font-mono">tx_valid passing</div>
      <div class="text-xs op-30 mt-1">(133 / 214 total, 81 taproot xfailed)</div>
    </div>
    <div v-click class="text-center p-6 border border-amber/20 rounded-lg">
      <div class="text-4xl font-bold text-amber font-mono">16</div>
      <div class="text-sm op-50 mt-2 font-mono">consensus flags</div>
      <div class="text-xs op-30 mt-1">P2SH → SegWit</div>
    </div>
  </div>

  <div v-click class="font-mono text-sm p-4 bg-white/5 rounded-lg">
    <div class="op-50 mb-2">Consensus flags implemented:</div>
    <div class="flex flex-wrap gap-2">
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">P2SH</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">DERSIG</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">STRICTENC</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">LOW_S</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">NULLDUMMY</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">SIGPUSHONLY</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">MINIMALDATA</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">CLEANSTACK</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">CLTV</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">CSV</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">WITNESS</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">MINIMALIF</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">NULLFAIL</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">DISCOURAGE_UPGRADABLE_NOPS</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">DISCOURAGE_UPGRADABLE_WITNESS</span>
      <span class="px-2 py-0.5 bg-amber/10 text-amber rounded text-xs">WITNESS_PUBKEYTYPE</span>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Benchmark: K vs Bitcoin Core</h2>

  <div class="grid grid-cols-2 gap-12 mb-8">
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">Summary</div>
      <div class="space-y-4">
        <div v-click class="flex justify-between items-baseline border-b border-white/10 pb-2">
          <span class="font-mono">Total inputs verified</span>
          <span class="text-amber font-bold text-xl font-mono">225,417</span>
        </div>
        <div v-click class="flex justify-between items-baseline border-b border-white/10 pb-2">
          <span class="font-mono">K avg latency</span>
          <span class="text-amber font-bold text-xl font-mono">0.64 ms</span>
        </div>
        <div v-click class="flex justify-between items-baseline border-b border-white/10 pb-2">
          <span class="font-mono">Core avg latency</span>
          <span class="font-bold text-xl font-mono op-60">0.38 ms</span>
        </div>
        <div v-click class="flex justify-between items-baseline">
          <span class="font-mono">Overhead</span>
          <span class="text-green-400 font-bold text-xl font-mono">1.7×</span>
        </div>
      </div>
    </div>
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">By Consensus Era</div>
      <div class="font-mono text-xs">
        <div class="grid grid-cols-5 gap-x-3 px-2 py-1 op-40 uppercase tracking-wider">
          <span>Era</span><span class="text-right">Inputs</span><span class="text-right">K</span><span class="text-right">Core</span><span class="text-right">Ratio</span>
        </div>
        <div v-click class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded mt-1 items-baseline">
          <span>pre-P2SH</span><span class="text-right text-amber">911</span><span class="text-right">0.62ms</span><span class="text-right op-50">0.02ms</span><span class="text-right op-50">31×</span>
        </div>
        <div v-click class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded mt-1 items-baseline">
          <span>P2SH</span><span class="text-right text-amber">8,840</span><span class="text-right">0.61ms</span><span class="text-right op-50">0.03ms</span><span class="text-right op-50">20×</span>
        </div>
        <div v-click class="grid grid-cols-5 gap-x-3 p-2 bg-green-500/10 border border-green-500/20 rounded mt-1 items-baseline">
          <span class="text-green-400">DERSIG</span><span class="text-right text-amber">59,509</span><span class="text-right text-green-400">0.59ms</span><span class="text-right op-50">1.25ms</span><span class="text-right text-green-400">0.5× ←</span>
        </div>
        <div v-click class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded mt-1 items-baseline">
          <span>CLTV</span><span class="text-right text-amber">42,192</span><span class="text-right">0.66ms</span><span class="text-right op-50">0.05ms</span><span class="text-right op-50">12×</span>
        </div>
        <div v-click class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded mt-1 items-baseline">
          <span>CSV</span><span class="text-right text-amber">43,833</span><span class="text-right">0.66ms</span><span class="text-right op-50">0.06ms</span><span class="text-right op-50">11×</span>
        </div>
        <div v-click class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded mt-1 items-baseline">
          <span>SegWit</span><span class="text-right text-amber">70,132</span><span class="text-right">0.67ms</span><span class="text-right op-50">0.07ms</span><span class="text-right op-50">9×</span>
        </div>
      </div>
    </div>
  </div>

  <div v-click class="p-3 border border-green-500/30 rounded font-mono text-sm text-green-400">
    → 1.7× average overhead. The ~0.64ms floor is Python serialization, not K execution — a native caller would close this gap. K outperforms Core on complex ECDSA-heavy scripts (DERSIG era: 0.5×).
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> CLI & Tooling</h2>

  <div class="grid grid-cols-2 gap-8">
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">REPL Features</div>
      <div class="space-y-3">
        <div v-click class="p-3 border border-white/10 rounded text-sm">
          <span class="text-amber font-mono">3 backends</span> — K Framework, Python engine, or local simulation; switch at runtime
        </div>
        <div v-click class="p-3 border border-white/10 rounded text-sm">
          <span class="text-amber font-mono">.sig</span> — set scriptSig tokens separately for full P2PKH / P2SH verification
        </div>
        <div v-click class="p-3 border border-white/10 rounded text-sm">
          <span class="text-amber font-mono">.flags p2sh,witness</span> — toggle any of the 16 consensus flags by name or bitmask
        </div>
        <div v-click class="p-3 border border-white/10 rounded text-sm">
          <span class="text-amber font-mono">ENCODE / HASH160</span> — encode a script to bytes and compute its P2SH address hash
        </div>
      </div>
    </div>
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">REPL Session</div>

```
btc> OP_1 OP_2 OP_ADD
  script: 515293 (3 bytes)

btc> .run
Stack (1 item):
  0: 0x03 (3)
Result: PASS

btc> .reset
Script cleared.

btc> OP_5 OP_3 OP_SUB
  script: 555394 (3 bytes)
btc> .run
Stack (1 item):
  0: 0x02 (2)
Result: PASS
```

</div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-8">
  <h2 class="!text-3xl font-mono !mb-6"><span class="text-amber">#</span> Live Demo: Bitcoin Script REPL</h2>
  <BitcoinRepl />
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Limitations & Future Work</h2>

  <div class="grid grid-cols-2 gap-12">
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">Current Limitation</div>
      <div class="space-y-3">
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-red-400 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Taproot execution rules</div>
            <div class="text-sm op-40">BIP 341/342 opcodes not yet implemented: OP_CHECKSIGADD, leaf versioning, annex handling — 5 xfailed script vectors, 81 xfailed tx vectors</div>
          </div>
        </div>
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-amber mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Tapscript block benchmarks</div>
            <div class="text-sm op-40">Benchmark dataset currently covers pre-Taproot era only</div>
          </div>
        </div>
      </div>
    </div>
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">Future Work</div>
      <div class="space-y-3">
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-white/30 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Full node integration</div>
            <div class="text-sm op-40">K verifier running on live mainnet alongside Bitcoin Core</div>
          </div>
        </div>
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-white/30 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Opcode weight support</div>
            <div class="text-sm op-40">First-class weight tracking in semantics</div>
          </div>
        </div>
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-white/30 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">End-to-end proofs with crypto hooks</div>
            <div class="text-sm op-40">P2PKH and P2WSH full-path proofs currently blocked on kore-rpc-booster support for ECDSA and hash function hooks</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

---

<div class="h-full flex flex-col items-center justify-center">
  <h2 class="!text-3xl font-mono !mb-8">Thank You</h2>
  <div class="flex items-center gap-12">
    <img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=https://bitcoin-script.onrender.com/&bgcolor=0a0a0a&color=f59e0b&format=svg" alt="QR code" class="w-36 h-36" />
    <div class="font-mono text-sm op-50 space-y-3 text-left">
      <div><span class="text-amber">slides</span> bitcoin-script.onrender.com</div>
      <div><span class="text-amber">source</span> github.com/zojize/bitcoin-script</div>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>
