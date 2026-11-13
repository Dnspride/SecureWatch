import React from "react";
import { Bell, Search, ShieldCheck, HelpCircle, Sun, Moon } from "lucide-react";
import { useRealtimeStore } from "../../store/realtimeStore";
import { useThemeStore } from "../../store/themeStore";

export const TopBar: React.FC = () => {
  const { wsConnected, liveAlerts } = useRealtimeStore();
  const { theme, toggleTheme } = useThemeStore();

  return (
    <header className="sticky top-0 z-20 flex h-16 w-full items-center justify-between border-b border-slate-200 bg-white px-6 shadow-xs transition-colors duration-200 dark:border-slate-800 dark:bg-[#0f172a]">
      {/* Global Search Bar */}
      <div className="relative w-80 md:w-96">
        <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
        <input
          type="text"
          placeholder="Search devices, alerts, indicators, identities..."
          className="w-full rounded-lg border border-slate-200 bg-slate-50 py-1.5 pl-10 pr-14 text-xs text-slate-800 placeholder-slate-400 transition-colors dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-100 dark:placeholder-slate-500 focus:bg-white dark:focus:bg-slate-800 focus:border-[#0078d4] focus:outline-none focus:ring-1 focus:ring-[#0078d4]"
        />
        <span className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-slate-200 bg-white px-1.5 py-0.5 text-[10px] font-mono text-slate-500 shadow-xs dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
          Ctrl K
        </span>
      </div>

      {/* Header Actions */}
      <div className="flex items-center gap-3">
        {/* Environment Status Badge */}
        <div className="hidden sm:flex items-center gap-1.5 rounded-lg border border-blue-200 bg-blue-50 px-2.5 py-1 text-[11px] font-medium text-[#0078d4] dark:border-blue-900/60 dark:bg-blue-950/40 dark:text-blue-300">
          <ShieldCheck className="h-3.5 w-3.5 text-[#0078d4] dark:text-blue-400" />
          <span>Defender for Endpoint • Active</span>
        </div>

        {/* WebSocket Real-time Status */}
        <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-2.5 py-1 dark:border-emerald-900/60 dark:bg-emerald-950/40">
          {wsConnected ? (
            <>
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-600 dark:bg-emerald-400" />
              </span>
              <span className="text-[11px] font-medium text-emerald-800 dark:text-emerald-300">Telemetry Streaming</span>
            </>
          ) : (
            <>
              <span className="h-2 w-2 rounded-full bg-slate-400 dark:bg-slate-500" />
              <span className="text-[11px] font-medium text-slate-600 dark:text-slate-400">Telemetry Connected</span>
            </>
          )}
        </div>

        {/* Light / Dark Mode Toggle Switch */}
        <button
          onClick={toggleTheme}
          title={`Switch to ${theme === "light" ? "Dark" : "Light"} Mode`}
          className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700 transition-all hover:bg-slate-100 hover:text-slate-900 dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-200 dark:hover:bg-slate-700 dark:hover:text-white cursor-pointer shadow-xs"
        >
          {theme === "light" ? (
            <>
              <Moon className="h-3.5 w-3.5 text-slate-600 dark:text-slate-300" />
              <span className="text-[11px]">Dark</span>
            </>
          ) : (
            <>
              <Sun className="h-3.5 w-3.5 text-amber-400" />
              <span className="text-[11px]">Light</span>
            </>
          )}
        </button>

        {/* Help Documentation */}
        <button
          className="rounded-lg border border-slate-200 p-2 text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white cursor-pointer"
          title="Defender Security Help & Documentation"
        >
          <HelpCircle className="h-4 w-4" />
        </button>

        {/* Notifications Icon */}
        <button
          className="relative rounded-lg border border-slate-200 p-2 text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-white cursor-pointer"
          title="Security Notifications"
        >
          <Bell className="h-4 w-4" />
          {liveAlerts.length > 0 && (
            <span className="absolute -right-1 -top-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-600 text-[9px] font-bold text-white shadow-xs">
              {liveAlerts.length}
            </span>
          )}
        </button>
      </div>
    </header>
  );
};
