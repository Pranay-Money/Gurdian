import React from 'react';
import { clsx } from 'clsx';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  icon?: React.ReactNode;
  iconPosition?: 'left' | 'right';
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', loading, icon, iconPosition = 'left', children, disabled, ...props }, ref) => {
    const baseStyles = `
      inline-flex items-center justify-center font-medium rounded-lg
      transition-all duration-150 ease-out
      focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2
      disabled:opacity-50 disabled:cursor-not-allowed
      active:scale-[0.98]
    `;

    const variants = {
      primary: `
        bg-blue-600 text-white hover:bg-blue-700
        focus-visible:ring-blue-500
        dark:bg-blue-500 dark:hover:bg-blue-600
      `,
      secondary: `
        bg-gray-100 text-gray-900 hover:bg-gray-200
        focus-visible:ring-gray-500
        dark:bg-gray-700 dark:text-gray-100 dark:hover:bg-gray-600
      `,
      danger: `
        bg-red-600 text-white hover:bg-red-700
        focus-visible:ring-red-500
        dark:bg-red-500 dark:hover:bg-red-600
      `,
      ghost: `
        bg-transparent text-gray-700 hover:bg-gray-100
        focus-visible:ring-gray-500
        dark:text-gray-300 dark:hover:bg-gray-800
      `,
    };

    const sizes = {
      sm: 'px-3 py-1.5 text-sm gap-1.5',
      md: 'px-4 py-2 text-base gap-2',
      lg: 'px-6 py-3 text-lg gap-2.5',
    };

    return (
      <button
        ref={ref}
        className={clsx(baseStyles, variants[variant], sizes[size], className)}
        disabled={disabled || loading}
        {...props}
      >
        {loading ? (
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
        ) : iconPosition === 'left' && icon ? (
          <span>{icon}</span>
        ) : null}
        {children}
        {iconPosition === 'right' && icon && !loading ? (
          <span>{icon}</span>
        ) : null}
      </button>
    );
  }
);

Button.displayName = 'Button';