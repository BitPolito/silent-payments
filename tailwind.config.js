/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        /* Ufficiali + sole sfumature sul segmento tra #f9f9f9 e #001ce0 */
        'bp-canvas': '#f9f9f9',
        'bp-blue': '#001ce0',
        'bp-50': '#eaecf7',
        'bp-100': '#e0e3f7',
        'bp-200': '#c7cdf4',
        'bp-300': '#9aa5f0',
        'bp-400': '#7d8bed',
        'bp-500': '#5f70ea',
        'bp-600': '#4155e7',
        'bp-700': '#253de4',
        'bp-800': '#142ee2',
        'blue-dark': '#001ce0',
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'system-ui', 'Segoe UI', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
