import fs from 'node:fs'
import path from 'node:path'

/** Keys / prefixes removed from an older UI layer; safe to drop from strings.js */
const REMOVE_KEYS = new Set([
  'flowAliceMeta',
  'flowDeriveTxReveal',
  'demoStoryTagline',
  'demoBeatPizza',
  'demoBeatSpAddr',
  'demoBeatPay',
  'demoBeatScan',
  'demoBobSpExplain',
  'demoBobSpLabel',
  'demoOverviewNext',
  'demoAliceWalletTitle',
  'demoAliceWalletLead',
  'demoAliceRecipientTitle',
  'demoAliceDeriveTitle',
  'demoBobWalletTitle',
  'demoScanExplainerTitle',
  'demoSummaryProse',
  'demoOutputsAliceTitle',
  'demoOutputsAliceHint',
  'demoOutputsBridgeTitle',
  'demoOutputsBridgeHint',
  'demoBobScanTitle',
  'demoSummaryRecap',
  'demoSummaryLineSp',
  'demoSummaryLineAlice',
  'demoSummaryLineBob',
  'demoCaptionSummaryDone',
  'demoChipInputs',
  'demoChipSpAddr',
  'demoChipOutputs',
  'demoChipOnChain',
  'demoChipObservers',
  'demoChipScanKeys',
  'demoChipFound',
  'demoToastOverview',
  'demoToastSend',
  'demoToastBridge',
  'demoToastReceive',
  'demoToastSummary',
  'demoToastSendOk',
  'demoToastSendFail',
  'demoToastRecvOk',
  'demoToastRecvFail',
  'demoOutcomeSendOk',
  'demoOutcomeSendFail',
  'demoOutcomeRecvOk',
  'demoOutcomeRecvFail',
  'demoTechnicalDetails',
  'demoFlowHeading',
  'demoFlowTxNote',
  'demoStory_linked',
  'demoStory_extra_tx_outputs',
  'demoStory_no_send_outputs',
  'demoStory_zero_key_sum',
  'demoStory_decoupled',
  'demoBridge',
  'demoExtraOutputs',
  'demoStepSend',
  'demoStepRecv',
  'demoSendTitle',
  'demoSendIntro',
  'demoRecvTitle',
  'demoRecvIntro',
  'demoRecipients',
  'demoLabels',
  'demoExpectedSend',
  'demoBridgeOutputs',
  'demoNodeTx',
  'demoNodeTxHint',
  'demoNodeSender',
  'demoNodeSenderHint',
  'demoNodeBridge',
  'demoNodeBridgeHint',
  'demoNodeReceiver',
  'demoNodeReceiverHint',
  'demoWalkthroughIntro',
  'demoWalkStep1',
  'demoWalkStep2',
  'demoWalkStep3',
  'demoWalkStep4',
  'demoPhaseSendExplain',
  'demoPhaseBridgeExplain',
  'demoPhaseRecvExplain',
  'demoBridgeTitle',
  'demoReceiverKeys',
  'demoRunHintSend',
  'demoRunHintRecv',
  'demoVerifyDetails',
  'demoNavSendOptional',
  'demoNavSendDone',
  'demoNavRecvOptional',
  'demoNavRecvDone',
  'demoPhaseSummaryTitle',
  'demoSummaryStory',
  'demoSummaryNote',
  'runSendDemo',
  'runRecvDemo',
  'modalTestsTitle',
  'modalTestsSubtitle',
  'sendTest',
  'receiveTest',
  'testIdPlaceholder',
  'showTests',
  'hideTests',
  'loadingList',
  'running',
  'invalidId',
  'clearResult',
  'modalAddrTitle',
  'modalAddrSubtitle',
  'genSafetyBanner',
  'genVanityInputHelp',
  'genPatternDropped',
  'bech32AlphabetTitle',
  'bech32MaxLen',
  'genGenerateNew',
  'genSearchPattern',
  'genResultLead',
  'genQrHint',
  'genAddressLabel',
  'genAddressHint',
  'genScanHint',
  'genSpendHint',
  'genPdfWarning',
  'vanityDifficultyEasy',
  'vanityDifficultyMedium',
  'vanityDifficultyHard',
  'patternPlaceholder',
  'advanced',
  'modeContains',
  'modePrefix',
  'modeSuffix',
  'matchMode',
  'downloading',
])

const REMOVE_PREFIXES = ['demoNarrative']

const file = path.join(path.resolve(import.meta.dirname, '..'), 'src/i18n/strings.js')
let src = fs.readFileSync(file, 'utf8')
const lines = src.split('\n')
const out = []
let skip = false
let removed = 0

for (let i = 0; i < lines.length; i++) {
  const line = lines[i]
  const m = line.match(/^\s+([a-zA-Z0-9_]+):\s*/)
  if (m) {
    const key = m[1]
    const shouldRemove =
      REMOVE_KEYS.has(key) || REMOVE_PREFIXES.some((p) => key.startsWith(p))
    if (shouldRemove) {
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
      if (/^\s{2,}[a-zA-Z0-9_]+:\s/.test(line)) {
        i--
      }
    }
    continue
  }
  out.push(line)
}

fs.writeFileSync(file, out.join('\n'))
console.log(`Removed ${removed} i18n entries`)
