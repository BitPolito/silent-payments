/**
 * Single-color SVG via CSS mask — follows `currentColor` (light/dark without a white file).
 * @param {{ src: string, className?: string, label?: string }} props
 */
export default function BpIcon({ src, className = 'h-4 w-4', label }) {
  const style = {
    maskImage: `url(${src})`,
    WebkitMaskImage: `url(${src})`,
    maskRepeat: 'no-repeat',
    WebkitMaskRepeat: 'no-repeat',
    maskPosition: 'center',
    WebkitMaskPosition: 'center',
    maskSize: 'contain',
    WebkitMaskSize: 'contain',
  }

  if (label) {
    return (
      <span className={`inline-flex shrink-0 items-center justify-center ${className}`} role="img" aria-label={label}>
        <span className="block h-full w-full bg-current" style={style} aria-hidden />
      </span>
    )
  }

  return <span className={`inline-block shrink-0 bg-current ${className}`} style={style} aria-hidden />
}
