import React from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Shield,
  LayoutDashboard,
  Users,
  ShieldCheck,
  KeyRound,
  UsersRound,
  Laptop,
  Activity,
  AlertTriangle,
  FileText,
  History,
  Settings,
  LogOut,
} from "lucide-react";
import { clsx } from "clsx";
import { useAuthStore } from "../../store/authStore";

interface NavItem {
  name: string;
  href: string;
  icon: React.ElementType;
  badge?: number;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: "INCIDENTS & ALERTS",
    items: [
      { name: "Overview", href: "/dashboard", icon: LayoutDashboard },
      { name: "Security Alerts", href: "/alerts", icon: AlertTriangle },
      { name: "SIEM Events", href: "/events", icon: Activity },
    ],
  },
  {
    title: "IDENTITY & ACCESS (IAM)",
    items: [
      { name: "Users", href: "/users", icon: Users },
      { name: "Roles & RBAC", href: "/roles", icon: ShieldCheck },
      { name: "Permissions", href: "/permissions", icon: KeyRound },
      { name: "User Groups", href: "/groups", icon: UsersRound },
    ],
  },
  {
    title: "ENDPOINTS (EDR)",
    items: [
      { name: "Managed Devices", href: "/devices", icon: Laptop },
    ],
  },
  {
    title: "AUDIT & COMPLIANCE",
    items: [
      { name: "Audit Logs", href: "/audit-logs", icon: History },
      { name: "Reports", href: "/reports", icon: FileText },
      { name: "System Settings", href: "/settings", icon: Settings },
    ],
  },
];

export const Sidebar: React.FC = () => {
  const location = useLocation();
  const { user, logout } = useAuthStore();

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-slate-200 bg-white text-slate-700 shadow-sm transition-colors duration-200 dark:border-slate-800 dark:bg-[#0f172a] dark:text-slate-300">
      {/* Brand Header */}
      <div className="flex h-16 items-center gap-3 border-b border-slate-200 px-5 bg-white transition-colors duration-200 dark:border-slate-800 dark:bg-[#0f172a]">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#0078d4] text-white shadow-sm dark:shadow-dark-glow">
          <Shield className="h-5 w-5" />
        </div>
        <div className="flex flex-col">
          <div className="flex items-center gap-2">
            <span className="text-base font-bold tracking-tight text-slate-900 dark:text-white">
              SecureWatch
            </span>
            <span className="rounded bg-blue-50 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-[#0078d4] border border-blue-200 dark:border-blue-800 dark:bg-blue-950/60 dark:text-blue-400">
              Defender XDR
            </span>
          </div>
          <span className="text-[10px] text-slate-500 dark:text-slate-400 font-medium tracking-wide">
            Endpoint & Identity Security
          </span>
        </div>
      </div>

      {/* Navigation Sections */}
      <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
        {navSections.map((section) => (
          <div key={section.title} className="space-y-1">
            <div className="px-3 pb-1 text-[11px] font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              {section.title}
            </div>
            {section.items.map((item) => {
              const isActive =
                item.href === "/dashboard"
                  ? location.pathname === "/dashboard"
                  : location.pathname.startsWith(item.href);
              const Icon = item.icon;

              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={clsx(
                    "group flex items-center justify-between px-3 py-2 text-xs transition-colors rounded-lg",
                    isActive
                      ? "bg-blue-50 text-[#0078d4] font-semibold border-l-4 border-[#0078d4] dark:bg-blue-950/40 dark:text-blue-300 dark:border-[#0078d4]"
                      : "text-slate-600 hover:bg-slate-100 hover:text-slate-900 font-medium dark:text-slate-300 dark:hover:bg-slate-800/60 dark:hover:text-white"
                  )}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon
                      className={clsx(
                        "h-4 w-4 shrink-0 transition-colors",
                        isActive
                          ? "text-[#0078d4] dark:text-blue-400"
                          : "text-slate-500 group-hover:text-slate-700 dark:text-slate-400 dark:group-hover:text-slate-200"
                      )}
                    />
                    <span>{item.name}</span>
                  </div>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-bold text-red-700 dark:bg-red-950 dark:text-red-400">
                      {item.badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* User Session Footer */}
      <div className="border-t border-slate-200 p-3 bg-slate-50 transition-colors duration-200 dark:border-slate-800 dark:bg-[#0b1120]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5 overflow-hidden">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-blue-100 text-xs font-bold text-[#0078d4] border border-blue-200 dark:bg-blue-950/60 dark:text-blue-400 dark:border-blue-800">
              {user?.full_name ? user.full_name[0].toUpperCase() : "A"}
            </div>
            <div className="truncate">
              <p className="truncate text-xs font-semibold text-slate-800 dark:text-slate-200">
                {user?.full_name || "Administrator"}
              </p>
              <p className="truncate text-[10px] text-slate-500 dark:text-slate-400">
                {user?.email || "admin@securewatch.io"}
              </p>
            </div>
          </div>
          <button
            onClick={() => logout()}
            title="Sign out of console"
            className="rounded-lg p-1.5 text-slate-500 transition-colors hover:bg-slate-200 hover:text-red-600 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-red-400 cursor-pointer"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
};
