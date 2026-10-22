/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        /* Brand colors, with theme-aware dark surfaces for utility classes. */
        'bp-canvas': '#f9f9f9',
        'bp-blue': '#001ce0',
        'bp-50': '#eaecf7',
        'bp-100': '#e0e3f7',
        'bp-200': '#c7cdf4',
        'bp-300': '#9aa5f0',
        'bp-400': '#7d8bed',
        'bp-500': 'rgb(var(--sp-tone-500) / <alpha-value>)',
        'bp-600': 'rgb(var(--sp-tone-600) / <alpha-value>)',
        'bp-700': 'rgb(var(--sp-tone-700) / <alpha-value>)',
        'bp-800': 'rgb(var(--sp-tone-800) / <alpha-value>)',
        'blue-dark': '#001ce0',
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'system-ui', 'Segoe UI', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
