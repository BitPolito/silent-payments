import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const stringsPath = path.join(root, 'src/i18n/strings.js')
const stringsSrc = fs.readFileSync(stringsPath, 'utf8')
const keys = [...stringsSrc.matchAll(/^\s+([a-zA-Z0-9_]+):/gm)].map((m) => m[1])

const dynamicPrefixes = [
  'flowStep_',
  'flowAside_',
  'edgeWhy_',
  'edgeStep_',
  'edgeSendIntro_',
  'edgeSendExpected_',
  'edgeRecvIntro_',
  'edgeDone_',
  'edgeCard_',
]

const codeFiles = []
function walk(dir) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.name.startsWith('.') || ent.name === 'node_modules') continue
    const p = path.join(dir, ent.name)
    if (ent.isDirectory()) walk(p)
    else if (/\.(jsx?|css)$/.test(ent.name) && !p.endsWith('strings.js')) codeFiles.push(p)
  }
}
walk(path.join(root, 'src'))
const code = codeFiles.map((f) => fs.readFileSync(f, 'utf8')).join('\n')

function isUsed(key) {
  if (dynamicPrefixes.some((p) => key.startsWith(p))) return true
  if (code.includes(`'${key}'`) || code.includes(`"${key}"`)) return true
  if (code.includes(`\`${key}\``)) return true
  return false
}

const unused = new Set(keys.filter((k) => !isUsed(k)))

let src = stringsSrc
const lines = src.split('\n')
const out = []
let skip = false
let removed = 0

for (let i = 0; i < lines.length; i++) {
  const line = lines[i]
  const m = line.match(/^\s+([a-zA-Z0-9_]+):\s*/)
  if (m) {
    if (unused.has(m[1])) {
      skip = true
      removed++
      continue
    }
    skip = false
    out.push(line)
    continue
  }
  if (skip) {
    if (/^\s{2,}[a-zA-Z0-9_]+:\s/.test(line) || /^\s*\},?\s*$/.test(line)) {
      skip = false
      if (/^\s{2,}[a-zA-Z0-9_]+:\s/.test(line)) i--
    }
    continue
  }
  out.push(line)
}

fs.writeFileSync(stringsPath, out.join('\n'))
console.log(`Removed ${removed} unused i18n entries`)
