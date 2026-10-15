import React from 'react';
import { clsx } from 'clsx';

interface SwitchProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string;
  description?: string;
  disabled?: boolean;
}

export const Switch = React.forwardRef<HTMLInputElement, SwitchProps>(
  ({ className, label, description, disabled, id, ...props }, ref) => {
    const switchId = id || React.useId();

    return (
      <label className={clsx('flex items-start gap-3 cursor-pointer', className)}>
        <div className="relative">
          <input
            ref={ref}
            type="checkbox"
            id={switchId}
            className={clsx(
              'peer h-5 w-5 appearance-none rounded-full border-2 transition-all duration-200',
              'border-gray-300 dark:border-gray-600',
              'checked:border-blue-500 checked:bg-blue-500',
              'checked:after:translate-x-full',
              'after:content-[""] after:absolute after:top-0.5 after:left-0.5 after:h-4 after:w-4 after:rounded-full after:bg-white after:shadow-lg after:transition-transform after:duration-200',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-gray-900',
              disabled && 'opacity-50 cursor-not-allowed peer-disabled:cursor-not-allowed'
            )}
            disabled={disabled}
            {...props}
          />
        </div>
        <div className="pt-1">
          {label && (
            <span className={clsx(
              'block text-sm font-medium',
              disabled ? 'text-gray-400 dark:text-gray-500' : 'text-gray-900 dark:text-gray-100'
            )}>
              {label}
            </span>
          )}
          {description && (
            <span className="block text-sm text-gray-500 dark:text-gray-400 mt-0.5">
              {description}
            </span>
          )}
        </div>
      </label>
    );
  }
);

Switch.displayName = 'Switch';