import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { FX_PRESETS, preloadFxAssets } from '../fx/presets'

/** @typedef {import('../fx/presets').FxPresetId} FxPresetId */

const SPAWN_MS = 48
const SPAWN_STOP_MS = 19000
const END_MS = 21000
const MAX_ACTIVE = 38

/**
 * @param {number} id
 * @param {import('../fx/presets').FX_PRESETS['a']} preset
 */
function spawnParticle(id, preset) {
  const sizeBase = preset.sizeMin + Math.random() * preset.sizeRange
  const giant = Math.random() < preset.giantChance
  const size = giant ? sizeBase * preset.giantScale : sizeBase
  return {
    id,
    left: Math.random() * 100,
    size,
    opacity: 0.88 + Math.random() * 0.12,
    duration: 1.15 + Math.random() * 0.75,
    drift: -14 + Math.random() * 28,
    sway: -22 + Math.random() * 44,
    wobble: -12 + Math.random() * 24,
    variantIdx: Math.floor(Math.random() * preset.sources.length),
  }
}

/**
 * @param {{ preset: FxPresetId | null, active: boolean, onDone?: () => void }} props
 */
export default function AmbientOverlay(props) {
  return props.active && props.preset ? <Animation key={props.preset} {...props} /> : null
}

function Animation({ preset, active, onDone }) {
  const layerRef = useRef(null)
  const [particles, setParticles] = useState(/** @type {ReturnType<typeof spawnParticle>[]} */ ([]))
  const [isDarkTheme, setIsDarkTheme] = useState(() => document.documentElement.classList.contains('dark'))
  const idRef = useRef(0)
  const onDoneRef = useRef(onDone)
  const timersRef = useRef({ spawn: /** @type {ReturnType<typeof setInterval> | null} */ (null), stop: null, end: null })

  useEffect(() => { onDoneRef.current = onDone }, [onDone])

  const cfg = preset ? FX_PRESETS[preset] : null

  useEffect(() => {
    preloadFxAssets()
  }, [])

  useEffect(() => {
    const layer = layerRef.current
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    // A body portal cannot paint above a modal dialog. A manual popover can,
    // without making the generator inert or capturing pointer/keyboard input.
    layer?.showPopover?.()
    return () => layer?.hidePopover?.()
  }, [])

  useEffect(() => {
    const syncTheme = () => setIsDarkTheme(document.documentElement.classList.contains('dark'))
    const obs = new MutationObserver(syncTheme)
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => obs.disconnect()
  }, [])

  useEffect(() => {
    const clearTimers = () => {
      if (timersRef.current.spawn) window.clearInterval(timersRef.current.spawn)
      if (timersRef.current.stop) window.clearTimeout(timersRef.current.stop)
      if (timersRef.current.end) window.clearTimeout(timersRef.current.end)
      timersRef.current = { spawn: null, stop: null, end: null }
    }

    const abort = () => {
      clearTimers()
      setParticles([])
      onDoneRef.current?.()
    }

    if (!active || !cfg) {
      clearTimers()
      return undefined
    }

    const reduceMotion =
      typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

    idRef.current = 0
    if (reduceMotion) {
      const t = window.setTimeout(() => onDoneRef.current?.(), 300)
      return () => window.clearTimeout(t)
    }

    const finish = () => {
      abort()
    }

    const tickSpawn = () => {
      const id = idRef.current++
      setParticles((prev) => {
        const next = [...prev, spawnParticle(id, cfg)]
        if (next.length > MAX_ACTIVE) return next.slice(next.length - MAX_ACTIVE)
        return next
      })
    }

    timersRef.current.spawn = window.setInterval(tickSpawn, SPAWN_MS)
    timersRef.current.stop = window.setTimeout(() => {
      if (timersRef.current.spawn) window.clearInterval(timersRef.current.spawn)
      timersRef.current.spawn = null
    }, SPAWN_STOP_MS)
    timersRef.current.end = window.setTimeout(finish, END_MS)

    const onVisibility = () => {
      if (document.hidden) abort()
    }

    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
      clearTimers()
    }
  }, [active, preset, cfg])

  const removeParticle = (id) => {
    setParticles((prev) => prev.filter((p) => p.id !== id))
  }

  if (!active || !cfg || typeof document === 'undefined') return null

  const tint = isDarkTheme ? cfg.tintDark : cfg.tintLight
  const invertDark = isDarkTheme && cfg.invertOnDark

  return createPortal(
    <div
      ref={layerRef}
      popover="manual"
      className={`sp-amb-layer ${isDarkTheme ? 'is-dark' : 'is-light'}${invertDark ? ' is-invert' : ''}`}
      style={{ background: tint }}
      aria-hidden
    >
      {particles.map((p) => (
        <img
          key={p.id}
          src={cfg.sources[p.variantIdx]}
          alt=""
          className="sp-amb-item"
          onAnimationEnd={() => removeParticle(p.id)}
          style={{
            left: `${p.left}%`,
            width: p.size,
            height: p.size,
            opacity: p.opacity,
            animationDuration: `${p.duration}s`,
            ['--sp-amb-drift']: `${p.drift}deg`,
            ['--sp-amb-sway']: `${p.sway}px`,
            ['--sp-amb-wobble']: `${p.wobble}deg`,
          }}
        />
      ))}
    </div>,
    document.body,
  )
}
