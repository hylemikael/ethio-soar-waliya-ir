/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#FFFFFF',
        surface: '#FFFFFF',
        'surface-elevated': '#F7F7F7',
        primary: '#2563EB',
        'primary-hover': '#1D4ED8',
        accent: '#0284C7',
        warning: '#D97706',
        danger: '#DC2626',
        critical: '#B91C1C',
        border: '#E5E7EB',
      },
    },
  },
  plugins: [],
}
