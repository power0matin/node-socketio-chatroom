'use strict';

module.exports = {
  content: ['./public/index.html', './public/assets/app.js'],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: 'var(--brand-color)',
          dark: 'var(--brand-dark)',
          light: 'var(--brand-light)',
        },
      },
    },
  },
  plugins: [],
};
