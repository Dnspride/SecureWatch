import React from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Users,
  Laptop,
  AlertTriangle,
  Activity,
  ShieldAlert,
  ArrowUpRight,
  TrendingUp,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import { dashboardService } from "../services/dashboard";
import { Card } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { RiskScore } from "../components/ui/RiskScore";
import { useThemeStore } from "../store/themeStore";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#0078d4",
};

export const DashboardPage: React.FC = () => {
  const { theme } = useThemeStore();
  const isDark = theme === "dark";

  const { data: stats, isLoading } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: () => dashboardService.getStats(),
    refetchInterval: 5000,
  });

  if (isLoading || !stats) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#0078d4] border-t-transparent" />
      </div>
    );
  }

  const alertPieData = Object.entries(stats.alerts_by_severity || {}).map(
    ([name, value]) => ({ name, value })
  );

  return (
    <div className="space-y-6">
      {/* Page Title & Breadcrumb */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Security Operations Center (SOC)
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Microsoft Defender Grade Telemetry, EDR Threat Detection & Identity Posture
          </p>
        </div>
        <div className="flex items-center gap-3 bg-white dark:bg-[#131b2e] border border-slate-200 dark:border-slate-800 px-3.5 py-1.5 rounded-xl shadow-xs">
          <span className="text-xs font-medium text-slate-600 dark:text-slate-300">Fleet Exposure Score:</span>
          <RiskScore score={stats.overall_risk_score} size="md" />
        </div>
      </div>

      {/* Top 6 KPI Cards Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-6">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">Total Users</span>
            <Users className="h-4 w-4 text-[#0078d4] dark:text-blue-400" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 dark:text-white">
              {stats.total_users}
            </span>
            <span className="text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              {stats.active_users} active
            </span>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">Enrolled Devices</span>
            <Laptop className="h-4 w-4 text-[#0078d4] dark:text-blue-400" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 dark:text-white">
              {stats.total_devices}
            </span>
            <span className="text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
              {stats.online_devices} online
            </span>
          </div>
        </Card>

        <Card className="p-4 border-red-200 bg-red-50/50 dark:border-red-900/40 dark:bg-red-950/20">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-red-700 dark:text-red-400">Critical Incidents</span>
            <ShieldAlert className="h-4 w-4 text-red-600 dark:text-red-400" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-red-700 dark:text-red-400">
              {stats.critical_alerts}
            </span>
            <span className="text-[11px] text-red-600 dark:text-red-300">unresolved</span>
          </div>
        </Card>

        <Card className="p-4 border-orange-200 bg-orange-50/50 dark:border-orange-900/40 dark:bg-orange-950/20">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-orange-700 dark:text-orange-400">High Alerts</span>
            <AlertTriangle className="h-4 w-4 text-orange-600 dark:text-orange-400" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-orange-700 dark:text-orange-400">
              {stats.high_alerts}
            </span>
            <span className="text-[11px] text-orange-600 dark:text-orange-300">unresolved</span>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400">Events Ingested</span>
            <Activity className="h-4 w-4 text-[#0078d4] dark:text-blue-400" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-slate-900 dark:text-white">
              {stats.total_events_today}
            </span>
            <span className="text-[11px] font-medium text-[#0078d4] dark:text-blue-400">today</span>
          </div>
        </Card>

        <Card className="p-4 border-amber-200 bg-amber-50/40 dark:border-amber-900/40 dark:bg-amber-950/20">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-amber-800 dark:text-amber-400">Failed Logins (24h)</span>
            <TrendingUp className="h-4 w-4 text-amber-700 dark:text-amber-400" />
          </div>
          <div className="mt-2.5 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-900 dark:text-amber-300">
              {stats.failed_logins_24h}
            </span>
            <span className="text-[11px] text-amber-700 dark:text-amber-400">attempts</span>
          </div>
        </Card>
      </div>

      {/* Visualizations Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Security Events Over Time */}
        <Card
          title="Telemetry & Incident Volume"
          subtitle="Events ingested vs critical threat detections over last 7 days"
          className="lg:col-span-2"
        >
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.events_over_time}>
                <defs>
                  <linearGradient id="totalColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0078d4" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#0078d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="critColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "#1e293b" : "#e2e8f0"} />
                <XAxis dataKey="date" stroke={isDark ? "#94a3b8" : "#64748b"} tick={{ fontSize: 11 }} />
                <YAxis stroke={isDark ? "#94a3b8" : "#64748b"} tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? "#0f172a" : "#ffffff",
                    borderColor: isDark ? "#1e293b" : "#e2e8f0",
                    borderRadius: "10px",
                    boxShadow: isDark ? "0 4px 12px rgba(0,0,0,0.5)" : "0 2px 4px rgba(0,0,0,0.06)",
                    color: isDark ? "#f8fafc" : "#0f172a",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="total"
                  stroke="#0078d4"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#totalColor)"
                  name="Total Telemetry"
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#critColor)"
                  name="Critical Alerts"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Alerts by Severity Donut */}
        <Card title="Active Alerts by Severity" subtitle="Breakdown of open alerts">
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={alertPieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {alertPieData.map((entry) => (
                    <Cell
                      key={`cell-${entry.name}`}
                      fill={SEVERITY_COLORS[entry.name] || "#94a3b8"}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: isDark ? "#0f172a" : "#ffffff",
                    borderColor: isDark ? "#1e293b" : "#e2e8f0",
                    borderRadius: "10px",
                    boxShadow: isDark ? "0 4px 12px rgba(0,0,0,0.5)" : "0 2px 4px rgba(0,0,0,0.06)",
                    color: isDark ? "#f8fafc" : "#0f172a",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-4 text-xs">
            {alertPieData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5 capitalize text-slate-600 dark:text-slate-400">
                <span
                  className="h-2.5 w-2.5 rounded-full"
                  style={{ backgroundColor: SEVERITY_COLORS[d.name] || "#94a3b8" }}
                />
                {d.name}: <span className="font-semibold text-slate-800 dark:text-slate-200">{d.value}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Two Column Lower Section */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Critical Alerts */}
        <Card
          title="Recent High & Critical Incidents"
          subtitle="Prioritized alerts requiring analyst triage"
          action={
            <Link
              to="/alerts"
              className="flex items-center gap-1 text-xs font-semibold text-[#0078d4] dark:text-blue-400 hover:underline"
            >
              View all incidents <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          }
        >
          <div className="space-y-3">
            {stats.recent_critical_alerts.length === 0 ? (
              <p className="py-8 text-center text-xs text-slate-400 dark:text-slate-500">
                No active critical alerts. Fleet posture is healthy.
              </p>
            ) : (
              stats.recent_critical_alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="flex items-center justify-between rounded-xl border border-slate-200 bg-slate-50 p-3 hover:border-slate-300 transition-colors dark:border-slate-800 dark:bg-slate-800/40 dark:hover:border-slate-700"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Badge variant={alert.severity as any}>
                        {alert.severity}
                      </Badge>
                      <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">
                        {alert.title}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      Endpoint: <span className="font-medium text-slate-700 dark:text-slate-300">{alert.device_name || "Unknown"}</span> • Time: {new Date(alert.detection_time).toLocaleTimeString()}
                    </p>
                  </div>
                  <Link
                    to={`/alerts/${alert.id}`}
                    className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 shadow-2xs"
                  >
                    Investigate
                  </Link>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Platform Recent Activity Audit */}
        <Card
          title="Administrative & Audit Activity"
          subtitle="Cryptographically verified immutable audit stream"
          action={
            <Link
              to="/audit-logs"
              className="flex items-center gap-1 text-xs font-semibold text-[#0078d4] dark:text-blue-400 hover:underline"
            >
              Full audit log <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          }
        >
          <div className="space-y-2">
            {stats.recent_activities.map((act) => (
              <div
                key={act.id}
                className="flex items-center justify-between rounded-lg p-2 text-xs hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-[10px] text-slate-400 dark:text-slate-500">
                    {new Date(act.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="font-semibold text-slate-800 dark:text-slate-200">{act.actor}</span>
                  <span className="rounded bg-slate-100 border border-slate-200 px-1.5 py-0.5 text-[10px] font-mono text-slate-700 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300">
                    {act.action}
                  </span>
                  <span className="text-slate-500 dark:text-slate-400 truncate max-w-xs">{act.resource}</span>
                </div>
                <Badge variant={act.result === "success" ? "success" : "critical"}>
                  {act.result}
                </Badge>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};
