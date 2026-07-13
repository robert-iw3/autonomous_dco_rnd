/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        obsidian: '#050505',
        glass: 'rgba(15, 23, 42, 0.6)',
        crimson: '#ef4444',
        cyan: '#06b6d4',
        amber: '#f59e0b',
        slate: {
          850: '#1e293b'
        }
      },
      fontFamily: {
        mono: ['"Fira Code"', 'monospace'],
        sans: ['Inter', 'sans-serif'],
      }
    }
  },
  plugins: []
};