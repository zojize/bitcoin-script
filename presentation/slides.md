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

<!--
Hi, I'm Jeff and this is Lawrence. We built an executable formal semantics
for Bitcoin Script in the K Framework. It passes 1,217 of Bitcoin Core's
1,222 script test vectors, and agrees with Bitcoin Core on every single one
of 225,000 real mainnet inputs we replayed. Over the next 10 minutes we'll
walk through what we built, how K made it tractable, and show a live demo
at the end.
-->

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> What is Bitcoin Script?</h2>

  <div class="grid grid-cols-2 gap-12">
    <div v-click>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">The Language</div>
      <ul class="space-y-3 text-lg">
        <li>Stack-based, Forth-like language</li>
        <li>Every Bitcoin transaction contains scripts</li>
        <li>~100 opcodes: crypto, arithmetic, flow control</li>
        <li>No loops — always terminates</li>
      </ul>
    </div>
    <div v-click>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">Why It's Hard to Specify</div>
      <ul class="space-y-3 text-lg">
        <li>Multi-phase execution: scriptSig, scriptPubKey, P2SH redeem, witness</li>
        <li>16 consensus flags with complex interactions</li>
        <li>Subtle encodings: CScriptNum, DER signatures, sighash variants</li>
        <li>Historical consensus bugs that can't be fixed without a chain split</li>
      </ul>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

<!--
Quick context.

[click] Bitcoin Script is a small stack-based language — think Forth — that
every Bitcoin transaction carries. About a hundred opcodes, no loops, so it
always terminates. Simple in principle.

[click] Under the hood it's surprisingly intricate. A single transaction
input chains up to four script phases. Sixteen consensus flags gate
different behavior. Bitcoin integers use a custom sign-magnitude encoding.
And there are historical bugs — like CHECKMULTISIG eating an extra stack
item — that can never be fixed because doing so would split the chain.
That combination of "small language" and "subtle behavior" is exactly where
formal semantics are valuable.
-->

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Why Formal Semantics?</h2>

  <div class="grid grid-cols-2 gap-12">
    <div v-click>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">The Problem</div>
      <ul class="space-y-3 text-lg">
        <li>Bitcoin Core's C++ is the <em>de facto</em> spec</li>
        <li>Consensus bugs = lost funds, chain splits</li>
        <li>No independent formal specification exists</li>
        <li>Hard to reason about opcode interactions</li>
      </ul>
    </div>
    <div v-click>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">K Framework Approach</div>
      <ul class="space-y-3 text-lg">
        <li>Executable formal semantics in K</li>
        <li>Mathematical rigor + runnable interpreter</li>
        <li>Prove properties about scripts</li>
        <li>Zero correctness mismatches on 225K real mainnet inputs</li>
      </ul>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

<!--
So why bother with formal semantics?

[click] Today, Bitcoin Core's C++ implementation is the de facto
specification. If Core and some other implementation disagree on a single
script, you get a chain split and people lose money. There's no independent
formal spec, and reasoning about how opcodes interact across phases and
flags is genuinely hard.

[click] K gives us an executable formal specification — not a document, not
pseudocode. The same K definition runs real scripts AND powers symbolic
proofs. We get mathematical rigor, a running interpreter, and the ability
to prove properties — all from one artifact. And the proof it works: zero
correctness mismatches against Core on 225,000 real mainnet inputs.
-->

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
      <div class="font-mono text-xs op-50 mb-2 uppercase tracking-wider">Modules</div>
      <div v-click class="space-y-1 font-mono text-sm">
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-semantics</span> config + phases</div>
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-sig</span> CHECKSIG/MULTISIG</div>
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-crypto</span> DER, sighash, ECDSA</div>
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-flow</span> IF/ELSE, CLTV/CSV</div>
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-decode</span> byte-level decoder</div>
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-arith</span> arithmetic opcodes</div>
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-stack</span> stack manipulation</div>
        <div class="px-2 py-1 border border-white/10 rounded"><span class="text-amber">script-num</span> CScriptNum encoding</div>
      </div>
      <div v-click class="mt-2 px-2 py-1 border border-amber/30 rounded font-mono text-xs text-amber">
        4 phases: scriptSig → scriptPubKey → p2sh-redeem → witness-v0
      </div>
    </div>
  </div>
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

<!--
Here's the core of our K definition — the configuration cell. K's
configuration is basically the state of the VM: the k cell holds the
current continuation, stack is the stack, phase tracks which of the four
script phases we're in, error holds a failure string, and the $-prefixed
cells are inputs from Python: the script bytes, the flags bitmask, and
transaction metadata for sighash.

[click] On the right: the K definition is split into eight modules, one per
concern. Config and phase orchestration, signature opcodes, cryptographic
encoding rules, flow control, the byte-level decoder, arithmetic, stack
manipulation, and a dedicated module for CScriptNum encoding.

[click] The whole thing is a state machine over up to four phases. The
phase cell transitions from scriptSig to scriptPubKey, and if the locking
script matches the P2SH pattern or is a witness program, we transition
again. Each phase has its own set of rules. This is all explicit, not
implicit.
-->

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

<!--
Three implementation problems worth calling out.

[click] First, multi-phase execution. P2SH redeem scripts are especially
tricky: you run scriptSig, save the stack, run scriptPubKey, and then if it
matches the P2SH pattern, you take the last item off the pre-saved stack,
reinterpret it as a script, and run it. Nested P2SH-SegWit adds another
layer. We model all these transitions as explicit phase rules in K.

[click] Second, CScriptNum. Bitcoin uses a custom sign-magnitude integer
encoding — not two's complement. Get it wrong on a negative zero edge case
and your consensus quietly diverges. This got its own 159-line module. We
also proved a roundtrip lemma that the Haskell prover backend uses as a
simplification rule.

[click] Third, sighash. We originally had Python pre-compute the
transaction hash and pass it into K as a blob. We've since moved sighash
computation directly into K — all three variants: legacy, BIP-143 for
SegWit, and BIP-341 tagged hash for Taproot. That means true end-to-end
verification from raw transaction bytes.
-->

---

<div class="h-full flex flex-col justify-center px-12">
  <h2 class="!text-3xl font-mono !mb-6"><span class="text-amber">#</span> Formal Proofs</h2>

  <div class="grid grid-cols-5 gap-8">
    <div class="col-span-3">

```haskell {maxHeight:'320px'}
// Proved: OP_ADD produces A+B for ALL valid inputs,
// not just specific test cases.
claim [add-correct]:
    <k> OP_ADD => .K ... </k>
    <stack>
      ListItem(intToScriptNum(A))
      ListItem(intToScriptNum(B)) REST
        =>
      ListItem(intToScriptNum(A +Int B)) REST
    </stack>
    <flags> _F </flags>
  requires A >=Int -2147483647
   andBool A <=Int  2147483647
   andBool B >=Int -2147483647
   andBool B <=Int  2147483647
```

</div>
    <div class="col-span-2 flex flex-col justify-center space-y-2">
      <div class="font-mono text-xs op-50 mb-1 uppercase tracking-wider">34 claims proven across 9 spec files</div>
      <div v-click class="space-y-2">
        <div class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">arithmetic</span> · <span class="op-60">OP_ADD, OP_NEGATE for all valid N</span></div>
        <div class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">symbolic</span> · <span class="op-60">OP_EQUAL, OP_NOT, OP_WITHIN</span></div>
        <div class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">timelock / htlc</span> · <span class="op-60">CLTV pass/fail, HTLC expiry paths</span></div>
        <div class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">phase / limits</span> · <span class="op-60">stack passing, CLEANSTACK, SIGPUSHONLY</span></div>
        <div class="p-2 border border-white/10 rounded font-mono text-xs"><span class="text-amber">historical-bugs</span> · <span class="op-60">MINIMALDATA, NULLDUMMY before/after flag activation</span></div>
      </div>
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

<!--
Because the semantics are in K, we get symbolic reasoning for free. On the
left is an actual proof claim we verified — it states that OP_ADD,
operating on two encoded script numbers A and B, produces the encoding of
A+B, for ALL valid A and B in the 32-bit signed range. The K prover
discharges this claim symbolically, so we know OP_ADD is correct for
every possible input, not just the few we could think to test.

[click] We've proven 34 such claims across 9 specification files — covering
arithmetic, symbolic properties like OP_EQUAL and OP_WITHIN, timelock and
HTLC scripts, phase transitions and consensus limits, and even historical
bugs like MINIMALDATA's behavior before and after flag activation.

[click] The key insight: the same K definition runs concrete tests AND
drives the prover. One specification, two modes — concrete execution and
symbolic verification. That's what you get from formal semantics that
Python alone can't give you.
-->

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Test Coverage</h2>

  <div v-click class="grid grid-cols-3 gap-8 mb-10">
    <div class="text-center p-6 border border-amber/20 rounded-lg">
      <div class="text-4xl font-bold text-amber font-mono">1,217</div>
      <div class="text-sm op-50 mt-2 font-mono">script_tests passing</div>
      <div class="text-xs op-30 mt-1">(5 taproot xfailed)</div>
    </div>
    <div class="text-center p-6 border border-amber/20 rounded-lg">
      <div class="text-4xl font-bold text-amber font-mono">133</div>
      <div class="text-sm op-50 mt-2 font-mono">tx_valid passing</div>
      <div class="text-xs op-30 mt-1">(133 / 214 total, 81 taproot xfailed)</div>
    </div>
    <div class="text-center p-6 border border-amber/20 rounded-lg">
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

<!--
[click] Test coverage. We pass 1,217 of Bitcoin Core's 1,222 script test
vectors — the five failures are all Taproot, which we haven't implemented
yet. On transaction vectors we pass 133, again with 81 Taproot failures.
And we implement 16 of Core's consensus verification flags, covering
everything from P2SH through SegWit.

[click] Here's the full flag list. This isn't a toy implementation —
standard encoding, DER signature strictness, low-S normalization, witness
pubkey typing, the upgradable NOPs policy — all there. Pre-Taproot, we are
feature complete.
-->

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Benchmark: K vs Bitcoin Core</h2>

  <div class="grid grid-cols-2 gap-12 mb-8">
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">Summary</div>
      <div v-click class="space-y-4">
        <div class="flex justify-between items-baseline border-b border-white/10 pb-2">
          <span class="font-mono">Total inputs verified</span>
          <span class="text-amber font-bold text-xl font-mono">225,417</span>
        </div>
        <div class="flex justify-between items-baseline border-b border-white/10 pb-2">
          <span class="font-mono">K avg latency</span>
          <span class="text-amber font-bold text-xl font-mono">0.64 ms</span>
        </div>
        <div class="flex justify-between items-baseline border-b border-white/10 pb-2">
          <span class="font-mono">Core avg latency</span>
          <span class="font-bold text-xl font-mono op-60">0.38 ms</span>
        </div>
        <div class="flex justify-between items-baseline">
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
        <div v-click class="space-y-1 mt-1">
          <div class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded items-baseline">
            <span>pre-P2SH</span><span class="text-right text-amber">911</span><span class="text-right">0.62ms</span><span class="text-right op-50">0.02ms</span><span class="text-right op-50">31×</span>
          </div>
          <div class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded items-baseline">
            <span>P2SH</span><span class="text-right text-amber">8,840</span><span class="text-right">0.61ms</span><span class="text-right op-50">0.03ms</span><span class="text-right op-50">20×</span>
          </div>
          <div class="grid grid-cols-5 gap-x-3 p-2 bg-green-500/10 border border-green-500/20 rounded items-baseline">
            <span class="text-green-400">DERSIG</span><span class="text-right text-amber">59,509</span><span class="text-right text-green-400">0.59ms</span><span class="text-right op-50">1.25ms</span><span class="text-right text-green-400">0.5× ←</span>
          </div>
          <div class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded items-baseline">
            <span>CLTV</span><span class="text-right text-amber">42,192</span><span class="text-right">0.66ms</span><span class="text-right op-50">0.05ms</span><span class="text-right op-50">12×</span>
          </div>
          <div class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded items-baseline">
            <span>CSV</span><span class="text-right text-amber">43,833</span><span class="text-right">0.66ms</span><span class="text-right op-50">0.06ms</span><span class="text-right op-50">11×</span>
          </div>
          <div class="grid grid-cols-5 gap-x-3 p-2 bg-white/5 rounded items-baseline">
            <span>SegWit</span><span class="text-right text-amber">70,132</span><span class="text-right">0.67ms</span><span class="text-right op-50">0.07ms</span><span class="text-right op-50">9×</span>
          </div>
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

<!--
Performance — because formal methods are often dismissed as too slow for
production.

[click] We replayed 225,000 real mainnet input verifications through both
our K semantics and Bitcoin Core's libbitcoinconsensus. K averages 0.64 ms
per input, Core averages 0.38 ms — so K is about 1.7 times slower on
average.

[click] Broken down by era, you see K's latency is remarkably flat — around
0.6 ms across all eras. That's because we're measuring the Python-to-LLVM
bridging overhead, not K itself. Look at the DERSIG row — highlighted
green. Those inputs have more complex ECDSA checks, so Core's cost rises
to 1.25 ms while K stays flat. K actually beats Core by 2x on heavy
signature-checking scripts.

[click] Takeaway: the 1.7x is not an inherent formal-methods tax. The floor
we're hitting is Python serialization. A native caller would close the gap,
and K already wins on the inputs that matter most — signature-heavy scripts.
This is viable for production use alongside a Bitcoin full node.
-->

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> CLI & Tooling</h2>

  <div class="grid grid-cols-2 gap-8">
    <div>
      <div class="font-mono text-sm op-50 mb-3 uppercase tracking-wider">REPL Features</div>
      <div v-click class="space-y-3">
        <div class="p-3 border border-white/10 rounded text-sm">
          <span class="text-amber font-mono">3 backends</span> — K Framework, Python engine, or local simulation; switch at runtime
        </div>
        <div class="p-3 border border-white/10 rounded text-sm">
          <span class="text-amber font-mono">.sig</span> — set scriptSig tokens separately for full P2PKH / P2SH verification
        </div>
        <div class="p-3 border border-white/10 rounded text-sm">
          <span class="text-amber font-mono">.flags p2sh,witness</span> — toggle any of the 16 consensus flags by name or bitmask
        </div>
        <div class="p-3 border border-white/10 rounded text-sm">
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

<!--
Beyond the semantics, we built a REPL to make the system accessible.

[click] Three backends that you can switch at runtime — the K Framework for
formal guarantees, a pure Python engine for quick local testing, and a
client-side simulator that runs even without a server.

The REPL also supports full scriptSig and scriptPubKey separation via dot
commands, toggleable consensus flags by name, and helper commands to
encode a script to bytes or compute a P2SH address hash — which, as you'll
see in a second, is exactly what you need to construct a P2SH transaction
end to end.
-->

---

<div class="h-full flex flex-col justify-center px-8">
  <h2 class="!text-3xl font-mono !mb-6"><span class="text-amber">#</span> Live Demo: Bitcoin Script REPL</h2>
  <BitcoinRepl />
</div>

<style>
.text-amber { color: #f59e0b; }
:deep(.slidev-layout) { background: #0a0a0a; color: #e5e5e5; }
</style>

<!--
Time to demo. This REPL is running the actual K Framework backend on a
Render-deployed server.

Quick demo — arithmetic:
  OP_1 OP_2 OP_ADD → .run → Stack: 3, PASS.

Now for a real P2SH verification. A "math puzzle" script: spend this UTXO
if you know the X such that X+2=5.

  1. Type the redeemScript:  OP_2 OP_ADD OP_5 OP_EQUAL
  2. Click ENCODE → get the bytes; click copy.
  3. Click HASH160 → get the 20-byte P2SH hash; click copy.
  4. Now .reset, and build the scriptPubKey:
       OP_HASH160 <paste-hash> OP_EQUAL
  5. Set the scriptSig — the answer plus the serialized redeemScript:
       .sig OP_3 <paste-bytes>
  6. Enable the P2SH flag:  .flags p2sh
  7. .run → PASS.

Try the wrong answer: .sig clear, then .sig OP_2 <bytes>, .run → FAIL.
That's a full P2SH round-trip running through formal K semantics in a
browser. No cheating.
-->

---

<div class="h-full flex flex-col justify-center px-16">
  <h2 class="!text-3xl font-mono !mb-8"><span class="text-amber">#</span> Limitations & Future Work</h2>

  <div class="grid grid-cols-2 gap-12">
    <div>
      <div class="font-mono text-sm op-50 mb-4 uppercase tracking-wider">Current Limitation</div>
      <div v-click class="space-y-3">
        <div class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-red-400 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Taproot execution rules</div>
            <div class="text-sm op-40">BIP 341/342 opcodes not yet implemented: OP_CHECKSIGADD, leaf versioning, annex handling — 5 xfailed script vectors, 81 xfailed tx vectors</div>
          </div>
        </div>
        <div class="flex items-start gap-3">
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
      <div v-click class="space-y-3">
        <div class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-white/30 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Full node integration</div>
            <div class="text-sm op-40">K verifier running on live mainnet alongside Bitcoin Core</div>
          </div>
        </div>
        <div class="flex items-start gap-3">
          <div class="w-2 h-2 rounded-full bg-white/30 mt-2 shrink-0"></div>
          <div>
            <div class="font-mono">Opcode weight support</div>
            <div class="text-sm op-40">First-class weight tracking in semantics</div>
          </div>
        </div>
        <div class="flex items-start gap-3">
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

<!--
What's left.

[click] On the limitations side: we don't yet implement Taproot execution
rules — BIP 341 and 342. That's OP_CHECKSIGADD, leaf versioning, annex
handling. It accounts for all our xfailed test cases. And our benchmark
dataset is pre-Taproot only, because we haven't run those scripts end to
end yet.

[click] On the future work side: we want to integrate this into a live
full node running next to Bitcoin Core, add first-class opcode weight
tracking to the semantics — important for block weight validation under
Taproot — and unblock end-to-end proofs by getting ECDSA and hash function
hooks supported in kore-rpc-booster, which would let us prove full P2PKH
and P2WSH verification paths rather than just the script-level pieces.
-->

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

<!--
That's the talk. QR code on the left takes you to the live slides and REPL
— same demo you just saw, running on Render. Source is on GitHub. Happy
to take questions.
-->
