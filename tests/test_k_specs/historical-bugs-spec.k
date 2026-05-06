// Historical Bitcoin Script bugs demonstrated via formal proofs.
//
// Each pair of claims shows a script that succeeds under old (permissive)
// consensus rules and fails under new (strict) rules — proving that the
// fix correctly prevents the exploit.

module HISTORICAL-BUGS-SPEC
  imports SCRIPT-VERIFICATION

  // =========================================================================
  // BIP 62 / MINIMALDATA: non-minimal CScriptNum encoding
  //
  // b"\x00\x00" is a non-minimal encoding of 0 (should be b"").
  // Before MINIMALDATA: accepted, script succeeds.
  // After MINIMALDATA: rejected, execution gets stuck (no rule matches).
  //
  // Script: <push 2 bytes: 0x00 0x00> OP_NOT = b"\x02\x00\x00\x91"
  // The NOT of 0 is 1 (truthy), so without MINIMALDATA the script passes.
  // =========================================================================

  // Pre-MINIMALDATA (flags=0): non-minimal zero accepted, NOT(0)=1, passes
  claim [non-minimal-zero-accepted-without-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x02\x00\x00\x91" </scriptPubKeyBytes> // <0x0000> NOT
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Post-MINIMALDATA (flags=64): non-minimal zero rejected
  claim [non-minimal-zero-rejected-with-flag]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "MINIMALDATA" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x02\x00\x00\x91" </scriptPubKeyBytes> // <0x0000> NOT
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 64 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // =========================================================================
  // BIP 147 / NULLDUMMY: CHECKMULTISIG dummy element malleability
  //
  // CHECKMULTISIG pops an extra "dummy" element due to an off-by-one bug.
  // Before NULLDUMMY: any value accepted as dummy (transaction malleability).
  // After NULLDUMMY: dummy must be empty bytes (OP_0).
  //
  // Script: scriptSig pushes dummy=0x01 (non-null) + dummy sig + pubkey count
  // scriptPubKey: OP_0 OP_0 OP_CHECKMULTISIG (0-of-0 multisig, always passes)
  // = b"\x00\x00\xae"
  //
  // scriptSig: OP_1 (non-null dummy) = b"\x51"
  // =========================================================================

  // Pre-NULLDUMMY (flags=0): non-null dummy accepted
  claim [nulldummy-non-null-accepted-without-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x51" </scriptSigBytes> // OP_1 (non-null dummy)
      <scriptPubKeyBytes> b"\x00\x00\xae" </scriptPubKeyBytes> // OP_0 OP_0 CHECKMULTISIG
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Post-NULLDUMMY (flags=16): non-null dummy rejected
  claim [nulldummy-non-null-rejected-with-flag]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "NULLDUMMY" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x51" </scriptSigBytes> // OP_1 (non-null dummy)
      <scriptPubKeyBytes> b"\x00\x00\xae" </scriptPubKeyBytes> // OP_0 OP_0 CHECKMULTISIG
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 16 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // =========================================================================
  // CLEANSTACK: extra stack elements as hidden data channel
  //
  // Before CLEANSTACK: scripts could leave extra items on the stack,
  // enabling a covert data channel and complicating static analysis.
  // After CLEANSTACK: exactly 1 item must remain.
  //
  // Script: OP_1 OP_1 = b"\x51\x51" (pushes two truthy values)
  // =========================================================================

  // Pre-CLEANSTACK (flags=0): two items on stack, top is truthy = passes
  claim [cleanstack-extra-items-accepted-without-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x51\x51" </scriptPubKeyBytes> // OP_1 OP_1
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Post-CLEANSTACK (flags=256): two items on stack = error
  claim [cleanstack-extra-items-rejected-with-flag]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "CLEANSTACK" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x51\x51" </scriptPubKeyBytes> // OP_1 OP_1
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 256 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // =========================================================================
  // DISCOURAGE_UPGRADABLE_NOPS: NOP reinterpretation attack
  //
  // Before this flag: OP_NOP1-10 were pure NOPs, so scripts containing
  // them would behave the same before and after a soft fork repurposed
  // them (e.g. CLTV = NOP2, CSV = NOP3). An attacker could broadcast
  // transactions relying on NOP behavior before the fork activated.
  // After this flag: using NOP1/NOP4-10 triggers an error, preventing
  // pre-fork exploitation.
  //
  // Script: OP_NOP1 OP_1 = b"\xb0\x51"
  // =========================================================================

  // Pre-DISCOURAGE_UPGRADABLE_NOPS (flags=0): NOP1 is harmless
  claim [upgradable-nop-accepted-without-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\xb0\x51" </scriptPubKeyBytes> // NOP1 OP_1
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Post-DISCOURAGE_UPGRADABLE_NOPS (flags=128): NOP1 rejected
  claim [upgradable-nop-rejected-with-flag]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "DISCOURAGE_UPGRADABLE_NOPS" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\xb0\x51" </scriptPubKeyBytes> // NOP1 OP_1
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 128 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

endmodule
