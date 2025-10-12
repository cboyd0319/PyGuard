/**
 * PyGuard Tailwind CSS Configuration
 * 
 * This configuration maps PyGuard design tokens to Tailwind CSS utilities.
 * It ensures consistency across all UI components and maintains WCAG 2.2 AA compliance.
 * 
 * Usage:
 * 1. Install Tailwind CSS: npm install -D tailwindcss
 * 2. Copy this file to your project root
 * 3. Run: npx tailwindcss init
 * 4. Replace content with this configuration
 * 
 * @see https://tailwindcss.com/docs/configuration
 */

module.exports = {
  content: [
    './pyguard/**/*.{py,html}',
    './docs/**/*.{md,html}',
  ],
  
  theme: {
    extend: {
      // Brand Colors
      colors: {
        brand: {
          DEFAULT: '#667EEA',
          dark: '#5A67D8',
          darker: '#4C51BF',
        },
        
        // Semantic Colors - WCAG 2.2 AA Compliant
        success: {
          DEFAULT: '#38A169',
          bg: '#C6F6D5',
          border: '#2F855A',
        },
        warning: {
          DEFAULT: '#D69E2E',
          bg: '#FEEBC8',
          border: '#B7791F',
        },
        danger: {
          DEFAULT: '#E53E3E',
          bg: '#FED7D7',
          border: '#C53030',
        },
        info: {
          DEFAULT: '#3182CE',
          bg: '#BEE3F8',
          border: '#2C5282',
        },
        
        // Severity Colors
        severity: {
          high: '#E53E3E',
          'high-bg': '#FFF5F5',
          'high-border': '#C53030',
          medium: '#D69E2E',
          'medium-bg': '#FFFAF0',
          'medium-border': '#B7791F',
          low: '#38A169',
          'low-bg': '#F0FDF4',
          'low-border': '#2F855A',
        },
      },
      
      // Typography
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          '"Helvetica Neue"',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'Monaco',
          '"Courier New"',
          'monospace',
        ],
      },
      
      fontSize: {
        'xs': ['0.75rem', { lineHeight: '1rem' }],
        'sm': ['0.875rem', { lineHeight: '1.25rem' }],
        'base': ['1rem', { lineHeight: '1.5rem' }],
        'lg': ['1.125rem', { lineHeight: '1.75rem' }],
        'xl': ['1.25rem', { lineHeight: '1.75rem' }],
        '2xl': ['1.5rem', { lineHeight: '2rem' }],
        '3xl': ['1.875rem', { lineHeight: '2.25rem' }],
        '4xl': ['2.25rem', { lineHeight: '2.5rem' }],
        '5xl': ['3rem', { lineHeight: '1' }],
      },
      
      // Spacing (4px base unit)
      spacing: {
        '0': '0',
        '1': '0.25rem',   // 4px
        '2': '0.5rem',    // 8px
        '3': '0.75rem',   // 12px
        '4': '1rem',      // 16px
        '5': '1.25rem',   // 20px
        '6': '1.5rem',    // 24px
        '8': '2rem',      // 32px
        '10': '2.5rem',   // 40px
        '12': '3rem',     // 48px
        '16': '4rem',     // 64px
        '20': '5rem',     // 80px
        '24': '6rem',     // 96px
      },
      
      // Border Radius
      borderRadius: {
        'none': '0',
        'sm': '0.375rem',
        'md': '0.5rem',
        'lg': '0.75rem',
        'xl': '1rem',
        '2xl': '1.5rem',
        'full': '9999px',
      },
      
      // Box Shadow
      boxShadow: {
        'sm': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'md': '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        'lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
        'xl': '0 20px 25px -5px rgba(0, 0, 0, 0.1)',
        '2xl': '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
        'inner': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.06)',
      },
      
      // Animation Duration
      transitionDuration: {
        'fast': '150ms',
        'base': '250ms',
        'slow': '350ms',
      },
      
      // Animation Easing
      transitionTimingFunction: {
        'standard': 'cubic-bezier(0.4, 0.0, 0.2, 1)',
        'decelerate': 'cubic-bezier(0.0, 0.0, 0.2, 1)',
        'accelerate': 'cubic-bezier(0.4, 0.0, 1, 1)',
      },
      
      // Z-Index Scale
      zIndex: {
        'base': '0',
        'dropdown': '1000',
        'sticky': '1100',
        'modal': '1200',
        'popover': '1300',
        'tooltip': '1400',
      },
      
      // Minimum Touch Target Size - WCAG 2.5.8
      minHeight: {
        'touch': '44px',
      },
      minWidth: {
        'touch': '44px',
      },
    },
  },
  
  plugins: [
    // Custom plugin for WCAG 2.2 AA utilities
    function({ addUtilities, theme }) {
      const newUtilities = {
        // Focus visible utilities - WCAG 2.4.7
        '.focus-ring': {
          'outline': `2px solid ${theme('colors.brand.DEFAULT')}`,
          'outline-offset': '2px',
        },
        '.focus-ring-inset': {
          'outline': `2px solid ${theme('colors.brand.DEFAULT')}`,
          'outline-offset': '-2px',
        },
        
        // Touch target utilities - WCAG 2.5.8
        '.touch-target': {
          'min-height': '44px',
          'min-width': '44px',
        },
        
        // Skip link utility
        '.skip-link': {
          'position': 'absolute',
          'top': '-40px',
          'left': '0',
          'background': theme('colors.gray.900'),
          'color': 'white',
          'padding': `${theme('spacing.3')} ${theme('spacing.4')}`,
          'text-decoration': 'none',
          'z-index': '100',
          '&:focus': {
            'top': '0',
          },
        },
      }
      
      addUtilities(newUtilities, ['responsive', 'focus', 'focus-visible'])
    },
  ],
  
  // Safelist important classes that might be used dynamically
  safelist: [
    'severity-high',
    'severity-medium',
    'severity-low',
    'severity-high-bg',
    'severity-medium-bg',
    'severity-low-bg',
  ],
}
