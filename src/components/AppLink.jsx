import { followsLocalLink, navigateTo } from '../utils/navigation'

export default function AppLink({ href, onClick, children, ...props }) {
  return <a {...props} href={href} onClick={(event) => {
    onClick?.(event)
    if (followsLocalLink(event, href)) {
      event.preventDefault()
      navigateTo(href)
    }
  }}>{children}</a>
}
