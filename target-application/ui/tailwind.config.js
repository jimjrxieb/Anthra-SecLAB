// data-dev:styles-tailwind-config
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx,js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Primary - Matrix green (security vibes)
        jade: {
          50: '#e6fff5',
          100: '#b3ffdf',
          200: '#80ffc9',
          300: '#4dffb3',
          400: '#1aff9d',
          500: '#00ff9d',
          600: '#00cc7d',
          700: '#00995e',
          800: '#00663e',
          900: '#00331f',
          DEFAULT: '#00ff9d',
          light: '#33ffb0',
        },
        // Secondary - Electric indigo
        crystal: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          DEFAULT: '#6366f1',
        },
        // Accent - Hot pink (warnings/highlights)
        gold: {
          50: '#fdf2f8',
          100: '#fce7f3',
          200: '#fbcfe8',
          300: '#f9a8d4',
          400: '#f472b6',
          500: '#ec4899',
          600: '#db2777',
          700: '#be185d',
          800: '#9d174d',
          900: '#831843',
          DEFAULT: '#f472b6',
        },
        ink: '#0a0a0f',           // Deeper black, almost void
        card: '#12121a',          // Subtle purple undertone
        snow: '#12121a',          // Card backgrounds
        'text-primary': '#e2e8f0', // Soft white
        'text-secondary': '#94a3b8', // Lighter slate
        'text-muted': '#64748b',   // Slate gray
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'ink-gradient':
          'radial-gradient(600px 300px at 10% 10%, rgba(0,168,107,0.12), transparent 60%)',
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [],
};
