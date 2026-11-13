import React from "react";
import { clsx } from "clsx";

interface StatusDotProps {
  status: "online" | "offline" | "critical" | "warning" | "pending" | string;
  label?: string;
}

const colorMap: Record<string, string> = {
  online: "bg-emerald-500",
  offline: "bg-slate-400 dark:bg-slate-500",
  critical: "bg-red-500 animate-pulse",
  warning: "bg-amber-500",
  pending: "bg-blue-500",
  pending_approval: "bg-blue-500",
  revoked: "bg-rose-500",
};

export const StatusDot: React.FC<StatusDotProps> = ({ status, label }) => {
  const normStatus = status?.toLowerCase() || "offline";
  return (
    <div className="inline-flex items-center gap-2">
      <span className="relative flex h-2 w-2">
        {normStatus === "online" && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
        )}
        <span
          className={clsx(
            "relative inline-flex h-2 w-2 rounded-full",
            colorMap[normStatus] || colorMap.offline
          )}
        />
      </span>
      {label && <span className="text-xs text-slate-700 dark:text-slate-300 capitalize font-medium">{label.replace("_", " ")}</span>}
    </div>
  );
};
