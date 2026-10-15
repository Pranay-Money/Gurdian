import React from 'react';
import { clsx } from 'clsx';

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  dot?: boolean;
}

export const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant = 'default', size = 'md', dot, children, ...props }, ref) => {
    const variants = {
      default: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
      success: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400',
      warning: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
      danger: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
      info: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
      outline: 'bg-transparent border border-gray-300 text-gray-700 dark:border-gray-600 dark:text-gray-300',
    };

    const sizes = {
      sm: 'px-2 py-0.5 text-xs gap-1',
      md: 'px-2.5 py-1 text-sm gap-1.5',
      lg: 'px-3 py-1 text-base gap-2',
    };

    return (
      <span
        ref={ref}
        className={clsx(
          'inline-flex items-center font-medium rounded-full',
          variants[variant],
          sizes[size],
          className
        )}
        {...props}
      >
        {dot && (
          <span
            className={clsx(
              'rounded-full',
              size === 'sm' && 'w-1.5 h-1.5',
              size === 'md' && 'w-2 h-2',
              size === 'lg' && 'w-2.5 h-2.5',
              variant === 'success' && 'bg-emerald-500',
              variant === 'warning' && 'bg-amber-500',
              variant === 'danger' && 'bg-red-500',
              variant === 'info' && 'bg-blue-500',
              variant === 'default' && 'bg-gray-500',
              variant === 'outline' && 'bg-current'
            )}
          />
        )}
        {children}
      </span>
    );
  }
);

Badge.displayName = 'Badge';

interface RiskBadgeProps {
  level: 'Low' | 'Medium' | 'High' | 'Critical';
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export const RiskBadge = ({ level, size = 'md', showLabel = true }: RiskBadgeProps) => {
  const variants: Record<string, BadgeProps['variant']> = {
    Low: 'success',
    Medium: 'warning',
    High: 'danger',
    Critical: 'danger',
  };

  const labels: Record<string, string> = {
    Low: 'Low Risk',
    Medium: 'Medium Risk',
    High: 'High Risk',
    Critical: 'Critical Risk',
  };

  return (
    <Badge variant={variants[level]} size={size} dot>
      {showLabel && labels[level]}
    </Badge>
  );
};

interface ActionBadgeProps {
  action: 'allow' | 'warn' | 'block';
  size?: 'sm' | 'md' | 'lg';
}

export const ActionBadge = ({ action, size = 'md' }: ActionBadgeProps) => {
  const variants: Record<string, BadgeProps['variant']> = {
    allow: 'success',
    warn: 'warning',
    block: 'danger',
  };

  const labels: Record<string, string> = {
    allow: 'Allowed',
    warn: 'Warned',
    block: 'Blocked',
  };

  return (
    <Badge variant={variants[action]} size={size} dot>
      {labels[action]}
    </Badge>
  );
};