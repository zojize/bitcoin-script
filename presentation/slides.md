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
  <div class="mt-12 text-xs op-30 font-mono">Jeff Zou · April 2026</div>
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
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">Example: P2PKH</div>

```
scriptSig:   <sig> <pubkey>
scriptPubKey: OP_DUP OP_HASH160
              <pubkeyhash>
              OP_EQUALVERIFY
              OP_CHECKSIG
```

  <div v-click class="mt-6 p-3 border border-amber/30 rounded font-mono text-sm">
    <span class="text-amber">→</span> Locks coins to a public key hash.<br>
    <span class="text-amber">→</span> Only the private key holder can spend.
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
        <li v-click>LLVM backend for production-grade speed</li>
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
    <flags> $FLAGS:Int </flags>
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
      <div class="text-xs op-30 mt-1">(81 taproot xfailed)</div>
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
        <div v-click class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded mt-1 items-baseline">
          <span>DERSIG</span><span class="text-right text-amber">59,509</span><span class="text-right">0.59ms</span><span class="text-right op-50">1.25ms</span><span class="text-right text-green-400">0.5×</span>
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
    → 1.7× overhead is viable for a full-node verifier running alongside Bitcoin Core
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
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">Commands</div>

```bash
# Execute script (Python engine)
bitcoin-script execute "OP_1 OP_2 OP_ADD"

# Verify scriptSig + scriptPubKey
bitcoin-script verify "<sig>" "<pubkey>"

# Interactive REPL (K backend)
bitcoin-script repl --backend k

# Verify mainnet chain (K backend)
bitcoin-script verify-chain --end 1000

# Benchmark K vs Bitcoin Core
bitcoin-script benchmark extract --source api
bitcoin-script benchmark run
bitcoin-script benchmark report
```

</div>
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">REPL Session</div>

```
btc> OP_1 OP_2 OP_ADD
  script: 515293 (3 bytes)

btc> .run
Executing 3 bytes...
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
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Roadmap</h2>

  <div class="grid grid-cols-2 gap-12">
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">Near-Term</div>
      <div class="space-y-3">
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-amber mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Feature-complete Tapscript</div>
            <div class="text-sm op-40">BIP 341/342: Schnorr, leaf versioning</div>
          </div>
        </div>
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-amber mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Full Core test coverage</div>
            <div class="text-sm op-40">Including Tapscript test vectors</div>
          </div>
        </div>
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-amber mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Tapscript block benchmarks</div>
            <div class="text-sm op-40">Extend dataset to post-Taproot era</div>
          </div>
        </div>
      </div>
    </div>
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">Long-Term</div>
      <div class="space-y-3">
        <div v-click class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-white/30 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Full node integration</div>
            <div class="text-sm op-40">K verifier running on live mainnet</div>
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
            <div class="font-mono">Formal proofs of properties</div>
            <div class="text-sm op-40">Prove invariants about script behavior</div>
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
  <div class="font-mono text-6xl font-bold text-amber mb-6">₿</div>
  <h2 class="!text-3xl font-mono !mb-4">Thank You</h2>
  <div class="font-mono text-sm op-40 space-y-2 text-center">
    <div>github.com/zojize/bitcoin-script</div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>
