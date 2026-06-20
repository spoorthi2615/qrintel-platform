/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      colors: {
        cyber: {
          950: '#040b14',
          900: '#060d1f',
          800: '#0d1b2e',
          700: '#112240',
          600: '#1e3a5f',
          500: '#2563eb',
          400: '#3b82f6',
        },
        safe: '#10b981',
        suspicious: '#f59e0b',
        malicious: '#ef4444',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'grid-pattern': 'linear-gradient(rgba(37,99,235,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(37,99,235,0.05) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan-line': 'scanLine 2s linear infinite',
      },
      keyframes: {
        glow: {
          from: { boxShadow: '0 0 5px #2563eb, 0 0 10px #2563eb' },
          to: { boxShadow: '0 0 20px #2563eb, 0 0 40px #2563eb' },
        },
        scanLine: {
          '0%': { top: '0%' },
          '100%': { top: '100%' },
        },
      }
    },
  },
  plugins: [],
}
