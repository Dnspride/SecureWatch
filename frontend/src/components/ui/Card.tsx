import React from "react";
import { clsx } from "clsx";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  action,
  children,
  className,
  ...props
}) => {
  return (
    <div
      className={clsx(
        "rounded-xl border border-slate-200 bg-white p-5 shadow-xs transition-all dark:border-slate-800 dark:bg-[#131b2e] dark:shadow-dark-card hover:border-slate-300 dark:hover:border-slate-700",
        className
      )}
      {...props}
    >
      {(title || subtitle || action) && (
        <div className="mb-4 flex items-center justify-between border-b border-slate-100 pb-3 dark:border-slate-800/80">
          <div>
            {title && (
              <h3 className="text-sm md:text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h3>
            )}
            {subtitle && (
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{subtitle}</p>
            )}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
};
