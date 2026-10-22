import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { FX_PRESETS } from '../fx/presets'

const LOOPS = 2

function createScene(preset) {
  const width = window.innerWidth
  const height = window.innerHeight
  const count = width < 640 ? 12 : 18
  const particles = Array.from({ length: count }, (_, id) => {
    // Mix small, medium and large silhouettes in every burst.
    const size = id % 5 === 0
      ? (width < 640 ? 96 + Math.random() * 32 : 112 + Math.random() * 48)
      : id % 2 === 0 ? 72 + Math.random() * 24 : 44 + Math.random() * 20
    return {
      id,
      size,
      left: Math.random() * Math.max(0, width - size),
      delay: id * 0.09,
      duration: 2.6 + Math.random() * 1.2,
      rotation: -12 + Math.random() * 24,
      sway: -12 + Math.random() * 24,
      source: preset.sources[id % preset.sources.length],
    }
  })
  return { height, particles, end: Math.ceil(Math.max(...particles.map(p => p.delay + p.duration * LOOPS)) * 1000) + 100 }
}

/** A bounded CSS burst: no spawning intervals or React updates during the fall. */
export default function AmbientOverlay(props) {
  return props.active && props.preset ? <Animation key={props.preset} {...props} /> : null
}

function Animation({ preset, onDone }) {
  const layerRef = useRef(null)
  const onDoneRef = useRef(onDone)
  const [scene] = useState(() => createScene(FX_PRESETS[preset]))
  useEffect(() => { onDoneRef.current = onDone }, [onDone])

  useEffect(() => {
    const layer = layerRef.current
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)')
    let finished = false
    const finish = () => {
      if (finished) return
      finished = true
      layer?.hidePopover?.()
      onDoneRef.current?.()
    }
    // Keep the decoration above the dialog, without taking focus or input.
    if (!motion.matches) layer?.showPopover?.()
    const timer = window.setTimeout(finish, motion.matches ? 0 : scene.end)
    const onVisibility = () => { if (document.hidden) finish() }
    const onMotion = () => { if (motion.matches) finish() }
    document.addEventListener('visibilitychange', onVisibility)
    motion.addEventListener('change', onMotion)
    // Snapshot travel distance avoids jumps when mobile browser chrome resizes.
    window.addEventListener('orientationchange', finish)
    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisibility)
      motion.removeEventListener('change', onMotion)
      window.removeEventListener('orientationchange', finish)
      layer?.hidePopover?.()
    }
  }, [scene])

  return createPortal(<div ref={layerRef} popover="manual" className="sp-amb-layer" aria-hidden="true" style={{ '--sp-amb-height': `${scene.height}px` }}>
    {scene.particles.map(p => <span key={p.id} className="sp-amb-item" style={{
      left: p.left,
      width: p.size,
      height: p.size,
      maskImage: `url("${p.source}")`,
      WebkitMaskImage: `url("${p.source}")`,
      animationDelay: `${p.delay}s`,
      animationDuration: `${p.duration}s`,
      animationIterationCount: LOOPS,
      '--sp-amb-drift': `${p.rotation}deg`,
      '--sp-amb-sway': `${p.sway}px`,
    }} />)}
  </div>, document.body)
}
