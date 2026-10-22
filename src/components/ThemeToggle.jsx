import { useState } from 'react'
import { ICON } from '../assets/icons'
import BpIcon from './BpIcon'

export default function ThemeToggle({ ariaLabel }) {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'))
  const toggle = () => {
    const next = !dark
    setDark(next)
    document.documentElement.classList.toggle('dark', next)
    localStorage.setItem('theme', next ? 'dark' : 'light')
  }
  return <button type="button" role="switch" aria-checked={dark} aria-label={ariaLabel} onClick={toggle} className="sp-header-control sp-theme-control">
    <span className="sp-theme-track"><span className="sp-theme-thumb"><BpIcon src={dark ? ICON.moon : ICON.sun} className="h-3.5 w-3.5 text-bp-blue" /></span></span>
  </button>
}
