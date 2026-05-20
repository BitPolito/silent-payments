import fs from 'node:fs'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '..')
const stringsPath = path.join(root, 'src/i18n/strings.js')
const stringsSrc = fs.readFileSync(stringsPath, 'utf8')
const keys = [...stringsSrc.matchAll(/^\s+([a-zA-Z0-9_]+):/gm)].map((m) => m[1])

const dynamicPrefixes = ['flowStep_', 'demoScenario_', 'flowAside_', 'demoMeta']
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

const unused = keys.filter((k) => !isUsed(k))
console.log(`unused: ${unused.length}`)
for (const k of unused) console.log(k)
