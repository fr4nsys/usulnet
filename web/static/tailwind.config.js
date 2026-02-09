/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "../../internal/web/templates/**/*.templ",
    "../../internal/web/templates/**/*.go",
    "./js/**/*.js"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#fff7f3',
          100: '#ffebe3',
          200: '#ffd4c7',
          300: '#ffb09a',
          400: '#ff8c5a',
          500: '#ff6b35',
          600: '#e55a2b',
          700: '#c04920',
          800: '#9a3b1a',
          900: '#7d3318',
          950: '#441708',
        },
        sand: {
          50: '#faf8f1',
          100: '#f4efde',
          200: '#e8dcbc',
          300: '#d9c492',
          400: '#c9a86a',
          500: '#bc8f4d',
          600: '#ae7a41',
          700: '#916137',
          800: '#764f31',
          900: '#61422b',
          950: '#352115',
        },
        dark: {
          500: '#30363d',
          600: '#21262d',
          700: '#161b22',
          800: '#0d1117',
          900: '#0a0a0f',
          950: '#050507',
        },
        dune: {
          sand: '#e6a23c',
          light: '#d4a574',
          surface: '#c9956a',
          glow: '#4a9eff',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideDown: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
