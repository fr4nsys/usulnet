/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.templ"],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#fff7f3', 100: '#ffebe3', 200: '#ffd4c7', 300: '#ffb09a',
          400: '#ff8c5a', 500: '#ff6b35', 600: '#e55a2b', 700: '#c04920',
          800: '#9a3b1a', 900: '#7d3318', 950: '#441708',
        },
        dark: {
          500: '#30363d', 600: '#21262d', 700: '#161b22',
          800: '#0d1117', 900: '#0a0a0f', 950: '#050507',
        },
      },
      fontFamily: {
        sans: ['IBM Plex Sans', 'system-ui', 'sans-serif'],
        display: ['Space Grotesk', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
