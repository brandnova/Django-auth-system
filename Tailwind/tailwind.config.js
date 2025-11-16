/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    './static/**/*.js',
    '**/templates/**/*.html',
    '**/static/**/*.js',
    '../**/templates/**/**/*.html',
    '../**/templates/**/*.html',
    '../**/templates/*.html',
    '../static/**/*.js',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
};
