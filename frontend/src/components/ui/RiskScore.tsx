import React from "react";
import { clsx } from "clsx";

interface RiskScoreProps {
  score: number; // 0 - 100
  size?: "sm" | "md" | "lg";
}

export const RiskScore: React.FC<RiskScoreProps> = ({ score, size = "md" }) => {
  const rounded = Math.round(score);

  const getVariant = () => {
    if (rounded >= 70) return "text-red-700 bg-red-50 border-red-200 dark:text-red-400 dark:bg-red-950/40 dark:border-red-900/50";
    if (rounded >= 40) return "text-orange-700 bg-orange-50 border-orange-200 dark:text-orange-400 dark:bg-orange-950/40 dark:border-orange-900/50";
    if (rounded >= 20) return "text-amber-800 bg-amber-50 border-amber-200 dark:text-amber-400 dark:bg-amber-950/40 dark:border-amber-900/50";
    return "text-emerald-700 bg-emerald-50 border-emerald-200 dark:text-emerald-400 dark:bg-emerald-950/40 dark:border-emerald-900/50";
  };

  const sizes = {
    sm: "px-2 py-0.5 text-xs font-semibold rounded-md",
    md: "px-3 py-1 text-xs md:text-sm font-bold rounded-lg",
    lg: "px-4 py-1.5 text-base md:text-lg font-bold rounded-xl",
  };

  return (
    <div
      className={clsx(
        "inline-flex items-center gap-1.5 border font-mono tracking-tight",
        getVariant(),
        sizes[size]
      )}
    >
      <span>{rounded}</span>
      <span className="text-[10px] font-sans opacity-70">/100 Exposure</span>
    </div>
  );
};
