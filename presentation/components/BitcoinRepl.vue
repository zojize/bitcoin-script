<script setup lang="ts">
import { ref, nextTick, computed } from 'vue'

const API_BASE = import.meta.env.DEV ? 'http://localhost:8787' : ''

interface HistoryEntry {
  type: 'input' | 'output' | 'error' | 'info'
  text: string
  copy?: string  // Optional: show a copy button, copies this value to input
}

interface LastResult {
  stack: string[]
  result: string
  error?: string
  hex?: string
  size?: number
}

const history = ref<HistoryEntry[]>([
  { type: 'info', text: 'Bitcoin Script REPL — type opcodes then press Run (or Enter)' },
  { type: 'info', text: 'Try: OP_1 OP_2 OP_ADD' },
])
const inputValue = ref('')
const asmTokens = ref<string[]>([])
const sigTokens = ref<string[]>([])
const flagsMask = ref(0)
const isLoading = ref(false)
const historyEl = ref<HTMLElement | null>(null)
const lastResult = ref<LastResult | null>(null)

const FLAGS: Record<string, number> = {
  p2sh: 1,
  strictenc: 2,
  dersig: 4,
  low_s: 8,
  nulldummy: 16,
  sigpushonly: 32,
  minimaldata: 64,
  cleanstack: 256,
  cltv: 512,
  csv: 1024,
  witness: 2048,
  minimalif: 8192,
  nullfail: 16384,
}
const backendAvailable = ref<boolean | null>(null)
const activeBackend = ref('local')       // 'local' | 'python' | 'k'
const availableBackends = ref<string[]>([])

const backendLabel = computed(() => {
  switch (activeBackend.value) {
    case 'k': return 'K Framework'
    case 'python': return 'Python Engine'
    default: return 'Local Sim'
  }
})

const currentScript = computed(() => asmTokens.value.join(' '))
const currentSig = computed(() => sigTokens.value.join(' '))
const flagsLabel = computed(() => {
  const active = Object.entries(FLAGS).filter(([_, v]) => (flagsMask.value & v) !== 0).map(([n]) => n.toUpperCase())
  return active.length > 0 ? active.join('|') : 'none'
})

// Check if backend is available on mount
async function checkBackend() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(2000) })
    if (res.ok) {
      const data = await res.json()
      backendAvailable.value = true
      activeBackend.value = data.backend
      availableBackends.value = data.backends ?? [data.backend]
    } else {
      backendAvailable.value = false
      activeBackend.value = 'local'
    }
  } catch {
    backendAvailable.value = false
    activeBackend.value = 'local'
  }
}
checkBackend()

async function cycleBackend() {
  const all = backendAvailable.value
    ? ['local', ...availableBackends.value]
    : ['local']
  const idx = all.indexOf(activeBackend.value)
  const next = all[(idx + 1) % all.length]

  if (next !== 'local' && backendAvailable.value) {
    // Tell server to switch
    try {
      await fetch(`${API_BASE}/backend`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ backend: next }),
      })
    } catch {
      // ignore — we'll still send per-request backend
    }
  }
  activeBackend.value = next
  addEntry('info', `Switched to ${backendLabel.value}`)
}

function scrollToBottom() {
  nextTick(() => {
    if (historyEl.value) {
      historyEl.value.scrollTop = historyEl.value.scrollHeight
    }
  })
}

function addEntry(type: HistoryEntry['type'], text: string, copy?: string) {
  history.value.push({ type, text, copy })
  scrollToBottom()
}

function copyToInput(value: string) {
  if (inputValue.value && !inputValue.value.endsWith(' ')) {
    inputValue.value += ' '
  }
  inputValue.value += value
}

async function handleSubmit() {
  const line = inputValue.value.trim()
  inputValue.value = ''
  if (!line) return

  addEntry('input', `btc> ${line}`)

  // Dot commands
  if (line.startsWith('.')) {
    const cmd = line.split(/\s+/)[0].toLowerCase()
    if (cmd === '.reset') {
      asmTokens.value = []
      sigTokens.value = []
      lastResult.value = null
      addEntry('info', 'Script cleared (scriptSig and scriptPubKey).')
    } else if (cmd === '.sig') {
      // .sig                  -> show current sig
      // .sig OP_1 OP_2        -> push tokens to sig buffer
      // .sig clear            -> clear sig
      const args = line.split(/\s+/).slice(1)
      if (args.length === 0) {
        addEntry('info', `scriptSig: ${sigTokens.value.length ? currentSig.value : '(empty)'}`)
      } else if (args[0].toLowerCase() === 'clear') {
        sigTokens.value = []
        addEntry('info', 'scriptSig cleared.')
      } else {
        sigTokens.value.push(...args)
        addEntry('info', `  scriptSig: ${currentSig.value}`)
      }
    } else if (cmd === '.flags') {
      // .flags                -> show
      // .flags p2sh,cltv      -> set by name
      // .flags 5              -> set numeric
      // .flags clear          -> reset to 0
      const args = line.split(/\s+/).slice(1)
      if (args.length === 0) {
        addEntry('info', `flags: ${flagsMask.value} (${flagsLabel.value})`)
        addEntry('info', `available: ${Object.keys(FLAGS).join(', ')}`)
      } else if (args[0].toLowerCase() === 'clear') {
        flagsMask.value = 0
        addEntry('info', 'flags cleared.')
      } else {
        const arg = args.join('').toLowerCase()
        if (/^(0x)?[0-9a-f]+$/i.test(arg) && !isNaN(parseInt(arg))) {
          flagsMask.value = parseInt(arg, arg.startsWith('0x') ? 16 : 10)
        } else {
          let mask = 0
          for (const name of arg.split(/[,|+]/)) {
            const v = FLAGS[name.trim()]
            if (v === undefined) {
              addEntry('error', `unknown flag: ${name}`)
              return
            }
            mask |= v
          }
          flagsMask.value = mask
        }
        addEntry('info', `flags: ${flagsMask.value} (${flagsLabel.value})`)
      }
    } else if (cmd === '.scripthash') {
      await scriptHash()
    } else if (cmd === '.script') {
      if (asmTokens.value.length === 0) {
        addEntry('info', 'Script is empty.')
      } else {
        addEntry('info', `Hex: ${lastResult.value?.hex ?? '(run first)'}`)
        addEntry('info', `Len: ${lastResult.value?.size ?? asmTokens.value.length} ${lastResult.value?.size ? 'bytes' : 'tokens'}`)
      }
    } else if (cmd === '.asm') {
      if (asmTokens.value.length === 0) {
        addEntry('info', 'Script is empty.')
      } else {
        addEntry('info', currentScript.value)
      }
    } else if (cmd === '.stack') {
      if (lastResult.value === null) {
        addEntry('info', 'No execution yet. Use .run first.')
      } else {
        if (lastResult.value.error) {
          addEntry('error', `Error: ${lastResult.value.error}`)
        }
        if (lastResult.value.stack.length > 0) {
          addEntry('info', `Stack (${lastResult.value.stack.length} item${lastResult.value.stack.length !== 1 ? 's' : ''}):`)
          lastResult.value.stack.forEach((item, i) => {
            addEntry('output', `  ${i}: ${item}`)
          })
        } else {
          addEntry('info', 'Stack is empty.')
        }
        const ok = lastResult.value.result === 'PASS'
        addEntry(ok ? 'output' : 'error', `Result: ${lastResult.value.result}`)
      }
    } else if (cmd === '.help') {
      addEntry('info', 'Commands:')
      addEntry('info', '  .run          Execute script')
      addEntry('info', '  .stack        Show stack from last execution')
      addEntry('info', '  .reset        Clear scriptPubKey + scriptSig')
      addEntry('info', '  .script       Show current script (hex)')
      addEntry('info', '  .asm          Show current script (ASM tokens)')
      addEntry('info', '  .sig [...]    Push scriptSig tokens, clear, or show')
      addEntry('info', '  .flags [...]  Set/show verification flags')
      addEntry('info', '  .scripthash   HASH160 of current scriptPubKey buffer')
      addEntry('info', '  .help         Show this help')
      addEntry('info', 'Input: OP_1, OP_DUP, OP_ADD, OP_CHECKSIG, 0xHEX, ...')
    } else if (cmd === '.run') {
      await executeScript()
    } else {
      addEntry('error', `Unknown command: ${cmd}`)
    }
    return
  }

  // Accumulate tokens
  const tokens = line.split(/\s+/).filter(Boolean)
  asmTokens.value.push(...tokens)
  addEntry('info', `  script: ${currentScript.value}`)
}

async function executeScript() {
  // Flush any pending input first
  const pending = inputValue.value.trim()
  if (pending) {
    addEntry('input', `btc> ${pending}`)
    const tokens = pending.split(/\s+/).filter(Boolean)
    asmTokens.value.push(...tokens)
    addEntry('info', `  script: ${currentScript.value}`)
    inputValue.value = ''
  }

  if (asmTokens.value.length === 0) {
    addEntry('info', 'Script is empty. Type some opcodes first.')
    return
  }

  if (activeBackend.value === 'local') {
    simulateExecution()
    return
  }

  isLoading.value = true
  try {
    const res = await fetch(`${API_BASE}/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        asm: currentScript.value,
        script_sig: currentSig.value,
        flags: flagsMask.value,
        backend: activeBackend.value,
      }),
    })
    const data = await res.json()

    lastResult.value = {
      stack: data.stack ?? [],
      result: data.result,
      error: data.error,
      hex: data.hex,
      size: data.size,
    }

    if (data.error) {
      addEntry('error', `Error: ${data.error}`)
    }
    if (data.stack && data.stack.length > 0) {
      addEntry('info', `Stack (${data.stack.length} item${data.stack.length !== 1 ? 's' : ''}):`)
      data.stack.forEach((item: string, i: number) => {
        addEntry('output', `  ${i}: ${item}`)
      })
    } else {
      addEntry('info', 'Stack is empty.')
    }
    const ok = data.result === 'PASS'
    addEntry(ok ? 'output' : 'error', `Result: ${data.result}`)
  } catch {
    addEntry('error', `Connection error — is the API server running?`)
    addEntry('info', 'Start it with: uv run python presentation/server.py')
    backendAvailable.value = false
    activeBackend.value = 'local'
  } finally {
    isLoading.value = false
  }
}

async function scriptHash() {
  if (asmTokens.value.length === 0) {
    addEntry('info', 'scriptPubKey buffer is empty.')
    return
  }
  if (activeBackend.value === 'local') {
    addEntry('error', '.scripthash requires a backend (Python or K).')
    return
  }
  try {
    const res = await fetch(`${API_BASE}/hash160`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asm: currentScript.value }),
    })
    const data = await res.json()
    if (data.error) {
      addEntry('error', `Error: ${data.error}`)
    } else {
      addEntry('output', `HASH160: 0x${data.hash160}`, `0x${data.hash160}`)
    }
  } catch {
    addEntry('error', 'Connection error')
  }
}

async function encodeScript() {
  if (asmTokens.value.length === 0) {
    addEntry('info', 'scriptPubKey buffer is empty.')
    return
  }
  if (activeBackend.value === 'local') {
    addEntry('error', 'Encoding requires a backend (Python or K).')
    return
  }
  try {
    const res = await fetch(`${API_BASE}/hash160`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asm: currentScript.value }),
    })
    const data = await res.json()
    if (data.error) {
      addEntry('error', `Error: ${data.error}`)
    } else {
      addEntry('output', `bytes (${data.script_hex.length / 2} bytes): 0x${data.script_hex}`, `0x${data.script_hex}`)
    }
  } catch {
    addEntry('error', 'Connection error')
  }
}

function simulateExecution() {
  // Simple local simulation for demo without backend
  const script = currentScript.value
  const tokens = script.split(/\s+/)
  const stack: number[] = []
  let error = ''

  try {
    for (const tok of tokens) {
      const upper = tok.toUpperCase().replace(/^OP_/, '')
      // Number opcodes
      const numMatch = upper.match(/^(\d+)$/)
      if (numMatch) {
        stack.push(parseInt(numMatch[1]))
        continue
      }
      if (upper === '0' || upper === 'FALSE') { stack.push(0); continue }
      if (upper === '1' || upper === 'TRUE') { stack.push(1); continue }
      if (upper === '1NEGATE') { stack.push(-1); continue }
      if (/^\d+$/.test(upper) && parseInt(upper) >= 1 && parseInt(upper) <= 16) {
        stack.push(parseInt(upper)); continue
      }
      // Arithmetic
      if (upper === 'ADD') {
        if (stack.length < 2) throw new Error('stack underflow')
        const b = stack.pop()!, a = stack.pop()!
        stack.push(a + b); continue
      }
      if (upper === 'SUB') {
        if (stack.length < 2) throw new Error('stack underflow')
        const b = stack.pop()!, a = stack.pop()!
        stack.push(a - b); continue
      }
      if (upper === 'MUL') {
        if (stack.length < 2) throw new Error('stack underflow')
        const b = stack.pop()!, a = stack.pop()!
        stack.push(a * b); continue
      }
      // Stack ops
      if (upper === 'DUP') {
        if (stack.length < 1) throw new Error('stack underflow')
        stack.push(stack[stack.length - 1]); continue
      }
      if (upper === 'DROP') {
        if (stack.length < 1) throw new Error('stack underflow')
        stack.pop(); continue
      }
      if (upper === 'SWAP') {
        if (stack.length < 2) throw new Error('stack underflow')
        const a = stack.pop()!, b = stack.pop()!
        stack.push(a, b); continue
      }
      if (upper === 'EQUAL') {
        if (stack.length < 2) throw new Error('stack underflow')
        const b = stack.pop()!, a = stack.pop()!
        stack.push(a === b ? 1 : 0); continue
      }
      if (upper === 'EQUALVERIFY') {
        if (stack.length < 2) throw new Error('stack underflow')
        const b = stack.pop()!, a = stack.pop()!
        if (a !== b) throw new Error('EQUALVERIFY failed')
        continue
      }
      if (upper === 'VERIFY') {
        if (stack.length < 1) throw new Error('stack underflow')
        const v = stack.pop()!
        if (v === 0) throw new Error('VERIFY failed')
        continue
      }
      if (upper === 'RETURN') { throw new Error('OP_RETURN') }
      if (upper === 'NOT') {
        if (stack.length < 1) throw new Error('stack underflow')
        stack.push(stack.pop()! === 0 ? 1 : 0); continue
      }
      if (upper === 'IF' || upper === 'NOTIF' || upper === 'ELSE' || upper === 'ENDIF') {
        // Skip flow control in simulation
        continue
      }
      // Unknown opcode — push as-is for demo
      error = `unsupported opcode: ${tok} (connect backend for full support)`
      break
    }
  } catch (e: any) {
    error = e.message
  }

  const stackItems = stack.map(v => `${v}`)
  const pass = !error && stack.length > 0 && stack[stack.length - 1] !== 0
  const resultStr = error ? 'FAIL' : (pass ? 'PASS' : 'FAIL')

  lastResult.value = {
    stack: stackItems,
    result: resultStr,
    error: error || undefined,
  }

  if (error) {
    addEntry('error', `Error: ${error}`)
  }
  if (stack.length > 0) {
    addEntry('info', `Stack (${stack.length} item${stack.length !== 1 ? 's' : ''}):`)
    stack.forEach((item, i) => {
      addEntry('output', `  ${i}: ${item}`)
    })
  } else {
    addEntry('info', 'Stack is empty.')
  }
  addEntry(pass ? 'output' : 'error', `Result: ${resultStr}`)
  addEntry('info', '(local simulation — start backend for full support)')
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault()
    handleSubmit()
  }
}

// Quick-insert buttons
const quickOps = [
  'OP_1', 'OP_2', 'OP_3', 'OP_ADD', 'OP_SUB', 'OP_DUP',
  'OP_EQUAL', 'OP_VERIFY', 'OP_DROP', 'OP_SWAP', 'OP_NOT',
]

function insertOp(op: string) {
  if (inputValue.value && !inputValue.value.endsWith(' ')) {
    inputValue.value += ' '
  }
  inputValue.value += op
}
</script>

<template>
  <div class="repl-container">
    <!-- Status bar -->
    <div class="status-bar">
      <span class="status-label">BITCOIN SCRIPT REPL</span>
      <span v-if="sigTokens.length > 0" class="status-chip" title="scriptSig buffer has tokens">SIG</span>
      <span v-if="flagsMask > 0" class="status-chip" :title="`flags: ${flagsLabel}`">{{ flagsLabel }}</span>
      <button class="backend-toggle" @click="cycleBackend" :title="`Click to switch backend (${availableBackends.length ? availableBackends.join(', ') + ', local' : 'local only'})`">
        <span class="status-dot" :class="activeBackend === 'k' ? 'dot-blue' : activeBackend === 'python' ? 'dot-green' : 'dot-amber'"></span>
        <span class="status-text">{{ backendLabel }}</span>
      </button>
    </div>

    <!-- Output history -->
    <div ref="historyEl" class="history">
      <div
        v-for="(entry, i) in history"
        :key="i"
        class="history-line"
        :class="[`line-${entry.type}`, { 'line-with-copy': entry.copy }]"
      >
        <span>{{ entry.text }}</span>
        <button
          v-if="entry.copy"
          class="copy-btn"
          :title="`Copy ${entry.copy} to input`"
          @click="copyToInput(entry.copy)"
        >copy →</button>
      </div>
      <div v-if="isLoading" class="history-line line-info animate-pulse">Executing...</div>
    </div>

    <!-- Quick ops -->
    <div class="quick-ops">
      <button
        v-for="op in quickOps"
        :key="op"
        class="op-btn"
        @click="insertOp(op)"
      >{{ op.replace('OP_', '') }}</button>
      <button class="op-btn op-btn-special" @click="encodeScript" title="Encode current buffer to raw bytes (for pushing as a redeemScript)">ENCODE</button>
      <button class="op-btn op-btn-special" @click="scriptHash" title="HASH160 of current scriptPubKey buffer">HASH160</button>
      <button class="op-btn op-btn-run" @click="executeScript">.run</button>
      <button class="op-btn op-btn-reset" @click="asmTokens = []; sigTokens = []; addEntry('info', 'Script cleared.')">.reset</button>
    </div>

    <!-- Input -->
    <div class="input-row">
      <span class="prompt">btc&gt;</span>
      <input
        v-model="inputValue"
        class="repl-input"
        placeholder="OP_1 OP_2 OP_ADD"
        spellcheck="false"
        autocomplete="off"
        @keydown="handleKeydown"
      >
      <button class="send-btn" :disabled="isLoading" @click="handleSubmit">
        {{ isLoading ? '...' : '↵' }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.repl-container {
  background: #111111;
  border: 1px solid rgba(245, 158, 11, 0.2);
  border-radius: 8px;
  font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', Consolas, monospace;
  font-size: 13px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  height: 380px;
}

.status-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  background: rgba(245, 158, 11, 0.06);
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

.status-label { color: rgba(255, 255, 255, 0.4); }
.status-chip {
  padding: 1px 6px;
  border: 1px solid rgba(245, 158, 11, 0.4);
  background: rgba(245, 158, 11, 0.1);
  color: #f59e0b;
  border-radius: 3px;
  font-size: 9px;
  letter-spacing: 0.08em;
}
.backend-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-left: auto;
  background: transparent;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 3px;
  padding: 2px 8px;
  cursor: pointer;
  font-family: inherit;
  font-size: inherit;
  text-transform: inherit;
  letter-spacing: inherit;
  transition: border-color 0.15s;
}
.backend-toggle:hover {
  border-color: rgba(255, 255, 255, 0.2);
}
.status-dot {
  width: 6px; height: 6px; border-radius: 50%;
}
.dot-green { background: #22c55e; box-shadow: 0 0 4px #22c55e; }
.dot-blue { background: #3b82f6; box-shadow: 0 0 4px #3b82f6; }
.dot-amber { background: #f59e0b; box-shadow: 0 0 4px #f59e0b; }
.dot-gray { background: #666; }
.status-text { color: rgba(255, 255, 255, 0.5); }

.history {
  flex: 1;
  overflow-y: auto;
  padding: 8px 12px;
  scrollbar-width: thin;
  scrollbar-color: rgba(245, 158, 11, 0.2) transparent;
}

.history-line {
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
}
.line-with-copy {
  display: flex;
  align-items: center;
  gap: 8px;
}
.line-with-copy > span {
  flex: 1;
}
.copy-btn {
  flex-shrink: 0;
  padding: 1px 6px;
  border: 1px solid rgba(59, 130, 246, 0.3);
  border-radius: 3px;
  background: transparent;
  color: rgba(59, 130, 246, 0.7);
  font-family: inherit;
  font-size: 10px;
  cursor: pointer;
  transition: all 0.15s;
}
.copy-btn:hover {
  border-color: #3b82f6;
  color: #3b82f6;
  background: rgba(59, 130, 246, 0.1);
}

.line-input { color: #e5e5e5; }
.line-output { color: #22c55e; }
.line-error { color: #ef4444; }
.line-info { color: rgba(255, 255, 255, 0.45); }

.quick-ops {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  padding: 6px 10px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(0, 0, 0, 0.3);
}

.op-btn {
  padding: 2px 8px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 4px;
  background: transparent;
  color: rgba(255, 255, 255, 0.5);
  font-family: inherit;
  font-size: 11px;
  cursor: pointer;
  transition: all 0.15s;
}
.op-btn:hover {
  border-color: rgba(245, 158, 11, 0.4);
  color: #f59e0b;
  background: rgba(245, 158, 11, 0.08);
}
.op-btn-special {
  border-color: rgba(59, 130, 246, 0.3);
  color: rgba(59, 130, 246, 0.8);
}
.op-btn-special:hover {
  border-color: #3b82f6;
  color: #3b82f6;
  background: rgba(59, 130, 246, 0.1);
}
.op-btn-run {
  border-color: rgba(34, 197, 94, 0.3);
  color: rgba(34, 197, 94, 0.7);
}
.op-btn-run:hover {
  border-color: #22c55e;
  color: #22c55e;
  background: rgba(34, 197, 94, 0.1);
}
.op-btn-reset {
  border-color: rgba(239, 68, 68, 0.3);
  color: rgba(239, 68, 68, 0.6);
}
.op-btn-reset:hover {
  border-color: #ef4444;
  color: #ef4444;
  background: rgba(239, 68, 68, 0.1);
}

.input-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-top: 1px solid rgba(245, 158, 11, 0.15);
  background: rgba(245, 158, 11, 0.03);
}

.prompt {
  color: #f59e0b;
  font-weight: bold;
  flex-shrink: 0;
}

.repl-input {
  flex: 1;
  background: transparent;
  border: none;
  outline: none;
  color: #e5e5e5;
  font-family: inherit;
  font-size: 13px;
  caret-color: #f59e0b;
}
.repl-input::placeholder { color: rgba(255, 255, 255, 0.2); }

.send-btn {
  padding: 2px 10px;
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 4px;
  background: transparent;
  color: #f59e0b;
  font-family: inherit;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.15s;
}
.send-btn:hover { background: rgba(245, 158, 11, 0.1); }
.send-btn:disabled { opacity: 0.3; cursor: default; }
</style>
