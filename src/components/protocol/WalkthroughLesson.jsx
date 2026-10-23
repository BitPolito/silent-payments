import { useLocale } from '../../i18n/useLocale'
import teaching from '../../utils/walkthroughTeaching.json'
import CopyableText from '../CopyableText'

export default function WalkthroughLesson({ phase, caseData, result }) {
  const { locale, tr } = useLocale()
  const lesson = teaching[locale].stages[phase]
  return <section className="sp-demo-lesson" data-testid="stage-teaching">
    <h2>{lesson.goal}</h2>
    <p>{lesson.knows}</p>
    <p className="sp-description">{lesson.outcome}</p>
    {!result && (phase === 'derive' || phase === 'scan') && <section className="sp-demo-expectations" data-testid="demo-expectations">
      <h3>{tr('learnReference')}</h3>
      <p className="sp-description text-xs">{tr('teachNotRun')}</p>
      {phase === 'derive'
        ? (caseData.sending?.expected_output_sets || []).map((set, index) => <div key={index} className="mt-2 space-y-2">
          {set.map((value, outputIndex) => <CopyableText key={outputIndex} label={`${tr('teachOutput')} ${outputIndex + 1} · ${tr('teachKey')}`} value={value} />)}
        </div>)
        : <div className="space-y-2">
          {(caseData.receiving?.expected_addresses || []).map((address, index) => <CopyableText key={index} label={`${tr('teachAddress')} ${index + 1}`} value={address} />)}
          {(caseData.receiving?.expected_outputs || []).map((output, index) => <div key={index}>
            <CopyableText label={`${tr('teachOutput')} ${index + 1} · ${tr('teachKey')}`} value={output.pub_key} />
            <CopyableText label={tr('teachTweak')} value={output.priv_key_tweak} />
          </div>)}
        </div>}
    </section>}
  </section>
}
