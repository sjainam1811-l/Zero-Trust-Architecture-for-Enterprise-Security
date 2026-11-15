/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        base: '#F6F8FA',
        surface: '#FFFFFF',
        raised: '#F1F4F8',
        border: {
          DEFAULT: '#D8DEE6',
          strong: '#C3CBD6',
        },
        blue: {
          DEFAULT: '#1D4ED8',
          hover: '#1E40AF',
          soft: '#EAF0FF',
        },
        text: {
          primary: '#0F172A',
          secondary: '#475569',
          muted: '#64748B',
        },
        status: {
          pass: '#15803D',
          'pass-soft': '#E8F5EC',
          fail: '#B91C1C',
          'fail-soft': '#FDECEC',
          warning: '#B45309',
          'warning-soft': '#FEF3E2',
        },
      },
      borderRadius: {
        card: '12px',
        control: '8px',
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
      fontSize: {
        xs: ['12px', '16px'],
        sm: ['13px', '18px'],
        base: ['14px', '20px'],
        lg: ['16px', '24px'],
        xl: ['18px', '26px'],
        '2xl': ['24px', '32px'],
        '3xl': ['28px', '36px'],
      },
      transitionDuration: {
        DEFAULT: '150ms',
      },
    },
  },
  plugins: [],
};
