/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#090d16',
        surface: '#111827',
        'surface-elevated': '#1f2937',
        primary: '#3b82f6',
        'primary-hover': '#2563eb',
        accent: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        critical: '#dc2626',
        border: '#1f293d',
      },
    },
  },
  plugins: [],
}
