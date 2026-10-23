import { STORY } from '../assets/icons'
import AppLink from './AppLink'
import BpIcon from './BpIcon'

export default function BackLink({ href, onClick, children }) {
  const content = <><BpIcon src={STORY.arrow} className="sp-return-icon" /><span>{children}</span></>
  return href
    ? <AppLink className="sp-back-link" href={href} onClick={onClick}>{content}</AppLink>
    : <button type="button" className="sp-back-link" onClick={onClick}>{content}</button>
}
