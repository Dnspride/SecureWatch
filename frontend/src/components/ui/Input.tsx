import React from "react";
import { clsx } from "clsx";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, icon, className, ...props }, ref) => {
    return (
      <div className="w-full">
        {label && (
          <label className="mb-1.5 block text-xs font-medium text-slate-700 dark:text-slate-300">
            {label}
          </label>
        )}
        <div className="relative">
          {icon && (
            <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5 text-slate-400 dark:text-slate-500">
              {icon}
            </div>
          )}
          <input
            ref={ref}
            className={clsx(
              "w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs md:text-sm text-slate-800 placeholder-slate-400 transition-colors dark:border-slate-700 dark:bg-slate-800/90 dark:text-slate-100 dark:placeholder-slate-500 focus:border-[#0078d4] focus:outline-none focus:ring-1 focus:ring-[#0078d4] disabled:bg-slate-50 dark:disabled:bg-slate-900 disabled:opacity-60",
              icon && "pl-10",
              error && "border-red-500 focus:border-red-500 focus:ring-red-500",
              className
            )}
            {...props}
          />
        </div>
        {error && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{error}</p>}
      </div>
    );
  }
);

Input.displayName = "Input";
