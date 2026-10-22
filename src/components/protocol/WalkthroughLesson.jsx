import { useLocale } from '../../i18n/useLocale'
import teaching from '../../utils/walkthroughTeaching.json'
import CopyableText from '../CopyableText'

const TERMS = { bob: ['scan', 'spend', 'outputs'], alice: ['inputs'], derive: ['secret', 'tweak', 'outputs'], scan: ['scan', 'spend', 'labels'] }

export default function WalkthroughLesson({ phase, caseData }) {
  const { locale, tr } = useLocale()
  const lesson = teaching[locale].stages[phase]
  return <section className="sp-lesson-aside sp-surface space-y-4 rounded-xl p-5 text-sm" data-testid="stage-teaching">
    <h2 className="font-bold">{tr('learnGoal')}</h2>
    <p>{lesson.goal}</p>
    <details>
      <summary>{tr('learnHow')}</summary>
      <p className="my-2"><strong>{tr('learnWho')}: </strong>{lesson.knows}</p>
      <p className="my-2"><strong>{tr('learnOutcome')}: </strong>{lesson.outcome}</p>
      <p className="my-2 text-xs">{tr('learnConceptual')}</p>
      <dl className="space-y-3">{TERMS[phase].map((term) => <div key={term}>
        <dt className="font-bold">{teaching[locale].terms[term].title}</dt>
        <dd>{teaching[locale].terms[term].definition}</dd>
      </div>)}</dl>
    </details>
    {(phase === 'derive' || phase === 'scan') && <details>
      <summary>{tr('learnReference')}</summary>
      <p className="my-2 text-xs">{tr('teachNotRun')}</p>
      {phase === 'derive'
        ? (caseData.sending?.expected_output_sets || []).map((set, index) => <div key={index} className="mt-2 space-y-2">
          <p>{tr('expected')} · {index + 1}</p>{set.map((value, outputIndex) => <CopyableText key={outputIndex} value={value} />)}
        </div>)
        : <div className="space-y-2">
          {(caseData.receiving?.expected_addresses || []).map((address, index) => <div key={index}><p>{tr('teachAddress')} {index + 1}</p><CopyableText value={address} /></div>)}
          {(caseData.receiving?.expected_outputs || []).map((output, index) => <div key={index}>
            <p>{tr('teachOutput')} {index + 1} · {tr('teachKey')}</p><CopyableText value={output.pub_key} />
            <p>{tr('teachTweak')}</p><CopyableText value={output.priv_key_tweak} />
          </div>)}
        </div>}
    </details>}
  </section>
}
