import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  Laptop,
  Search,
  KeyRound,
  Copy,
  CheckCircle2,
  Clock,
  ShieldCheck,
  AlertCircle,
  Terminal,
  X,
  RefreshCw,
  Server,
  Filter,
} from "lucide-react";
import { deviceService } from "../services/devices";
import { Device, EnrollmentTokenResponse } from "../types";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { StatusDot } from "../components/ui/StatusDot";
import { RiskScore } from "../components/ui/RiskScore";
import { DataTable, Column } from "../components/ui/DataTable";

export const DevicesPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");

  // Enrollment Modal State
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [hoursValid, setHoursValid] = useState<number>(24);
  const [requiresApproval, setRequiresApproval] = useState<boolean>(false);
  const [department, setDepartment] = useState<string>("");
  const [generatedToken, setGeneratedToken] = useState<EnrollmentTokenResponse | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [selectedOS, setSelectedOS] = useState<"windows" | "linux">("windows");
  const [tokenError, setTokenError] = useState<string | null>(null);

  // 1. Fetch devices
  const { data: devicesData, isLoading, refetch } = useQuery({
    queryKey: ["devices", search, statusFilter],
    queryFn: () =>
      deviceService.getDevices({
        search: search || undefined,
        status: statusFilter || undefined,
        page_size: 50,
      }),
  });

  // 2. Generate Enrollment Token Mutation
  const tokenMutation = useMutation({
    mutationFn: async () => {
      setTokenError(null);
      return await deviceService.createEnrollmentToken({
        hours_valid: hoursValid,
        requires_approval: requiresApproval,
        department: department || undefined,
      });
    },
    onSuccess: (data: EnrollmentTokenResponse) => {
      setGeneratedToken(data);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (err: any) => {
      const msg = err?.response?.data?.detail || err?.message || "Failed to generate enrollment token";
      setTokenError(typeof msg === "string" ? msg : JSON.stringify(msg));
    },
  });

  const handleCopyText = (text: string, isCmd: boolean = false) => {
    navigator.clipboard.writeText(text);
    if (isCmd) {
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    } else {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    }
  };

  const getCliCommand = (token: string, os: "windows" | "linux") => {
    const serverUrl = window.location.hostname === "localhost" ? "http://localhost:8000" : window.location.origin;
    if (os === "windows") {
      return `python main.py --enroll --server-url ${serverUrl} --token ${token}`;
    }
    return `python3 main.py --enroll --server-url ${serverUrl} --token ${token}`;
  };

  const devicesList = devicesData?.items || [];
  const onlineCount = devicesList.filter((d) => d.status === "online").length;
  const criticalCount = devicesList.filter((d) => d.status === "critical" || d.risk_score >= 50).length;

  const columns: Column<Device>[] = [
    {
      key: "hostname",
      header: "Endpoint Hostname",
      render: (d) => (
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-50 text-[#0078d4] dark:bg-blue-950/60 dark:text-blue-400">
            <Laptop className="h-4 w-4" />
          </div>
          <div>
            <p className="font-semibold text-slate-900 hover:text-[#0078d4] dark:text-slate-100 dark:hover:text-blue-400 transition-colors">
              {d.hostname}
            </p>
            <p className="text-[11px] text-slate-400 dark:text-slate-500 font-mono">{d.id.slice(0, 8)}...</p>
          </div>
        </div>
      ),
    },
    {
      key: "os",
      header: "OS & Arch",
      render: (d) => (
        <span className="text-xs text-slate-700 dark:text-slate-300 font-medium">
          {d.os_name} {d.os_version} <span className="text-slate-400">({d.os_arch})</span>
        </span>
      ),
    },
    {
      key: "network",
      header: "IP Address",
      render: (d) => (
        <div className="text-xs font-mono">
          <p className="text-slate-800 dark:text-slate-200">{d.private_ip || "—"}</p>
          {d.public_ip && <p className="text-[10px] text-slate-400 dark:text-slate-500">{d.public_ip}</p>}
        </div>
      ),
    },
    {
      key: "agent",
      header: "Agent Version",
      render: (d) => (
        <span className="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-mono text-[#0078d4] dark:bg-slate-800 dark:text-blue-400 border border-slate-200 dark:border-slate-700">
          v{d.agent_version || "1.0.0"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (d) => <StatusDot status={d.status as any} label={d.status} />,
    },
    {
      key: "risk",
      header: "Risk Score",
      render: (d) => <RiskScore score={d.risk_score} size="sm" />,
    },
    {
      key: "heartbeat",
      header: "Last Heartbeat",
      render: (d) => (
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {d.last_heartbeat ? new Date(d.last_heartbeat).toLocaleTimeString() : "Never"}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner & Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Endpoint Device Management
            </h1>
            <span className="rounded-md bg-blue-50 px-2 py-0.5 text-xs font-medium text-[#0078d4] dark:bg-blue-950/60 dark:text-blue-400 border border-blue-200 dark:border-blue-800">
              EDR Agent Fleet
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Monitor enrolled enterprise endpoints, security agent status, system posture, and telemetry stream health.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            Refresh
          </Button>
          <Button
            onClick={() => {
              setShowTokenModal(true);
              setGeneratedToken(null);
              setTokenError(null);
            }}
            icon={<KeyRound className="h-4 w-4" />}
          >
            Enroll New Device
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="flex items-center gap-4 p-4">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-50 text-[#0078d4] dark:bg-blue-950/60 dark:text-blue-400">
            <Laptop className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Total Enrolled Devices</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">{devicesList.length}</p>
          </div>
        </Card>

        <Card className="flex items-center gap-4 p-4">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600 dark:bg-emerald-950/60 dark:text-emerald-400">
            <CheckCircle2 className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Online & Streaming</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">{onlineCount}</p>
          </div>
        </Card>

        <Card className="flex items-center gap-4 p-4">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-amber-50 text-amber-600 dark:bg-amber-950/60 dark:text-amber-400">
            <Clock className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">Heartbeat Interval</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">60s</p>
          </div>
        </Card>

        <Card className="flex items-center gap-4 p-4">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-red-50 text-red-600 dark:bg-red-950/60 dark:text-red-400">
            <AlertCircle className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">High Risk / Alerted</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">{criticalCount}</p>
          </div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full sm:w-auto">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by hostname, IP address, MAC or OS platform..."
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-10 pr-4 text-xs text-slate-800 placeholder-slate-400 transition-colors dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 dark:placeholder-slate-500 focus:border-[#0078d4] focus:outline-none focus:ring-1 focus:ring-[#0078d4]"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="h-4 w-4 text-slate-400 dark:text-slate-500 hidden sm:block" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full sm:w-44 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-800 transition-colors dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 focus:border-[#0078d4] focus:outline-none"
          >
            <option value="">All Statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="unhealthy">Unhealthy</option>
            <option value="critical">Critical</option>
            <option value="pending_approval">Pending Approval</option>
            <option value="revoked">Revoked</option>
          </select>
        </div>
      </div>

      {/* Devices DataTable */}
      <DataTable
        columns={columns}
        data={devicesList}
        isLoading={isLoading}
        onRowClick={(d) => navigate(`/devices/${d.id}`)}
        emptyMessage="No matching endpoint devices found. Click 'Enroll New Device' to add an endpoint."
      />

      {/* Enrollment Token Modal */}
      {showTokenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-xl rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl transition-all dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 text-[#0078d4] dark:bg-blue-950/60 dark:text-blue-400">
                  <KeyRound className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-white">
                    Enroll Endpoint Agent
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Generate secure single-device enrollment credentials and agent onboarding script.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setShowTokenModal(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Error Notification */}
            {tokenError && (
              <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
                <div className="flex items-center gap-2 font-semibold">
                  <AlertCircle className="h-4 w-4 shrink-0" />
                  <span>Error generating token:</span>
                </div>
                <p className="mt-1">{tokenError}</p>
              </div>
            )}

            {!generatedToken ? (
              /* Token Configuration Form */
              <div className="mt-5 space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Token Expiration Window
                  </label>
                  <select
                    value={hoursValid}
                    onChange={(e) => setHoursValid(Number(e.target.value))}
                    className="w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 focus:border-[#0078d4] focus:outline-none"
                  >
                    <option value={1}>1 Hour (Quick Setup)</option>
                    <option value={12}>12 Hours</option>
                    <option value={24}>24 Hours (Recommended)</option>
                    <option value={72}>3 Days</option>
                    <option value={168}>7 Days</option>
                  </select>
                  <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                    Once expired, this token cannot be used to register new devices.
                  </p>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Target Department / Organizational Unit (Optional)
                  </label>
                  <input
                    type="text"
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    placeholder="e.g. Security Operations, Engineering, IT Admin"
                    className="w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs text-slate-800 placeholder-slate-400 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500 focus:border-[#0078d4] focus:outline-none"
                  />
                </div>

                <div className="flex items-center gap-3 rounded-xl border border-slate-200 p-3 bg-slate-50 dark:border-slate-800 dark:bg-slate-800/40">
                  <input
                    type="checkbox"
                    id="requireApproval"
                    checked={requiresApproval}
                    onChange={(e) => setRequiresApproval(e.target.checked)}
                    className="h-4 w-4 rounded border-slate-300 text-[#0078d4] focus:ring-[#0078d4] dark:border-slate-600 dark:bg-slate-700"
                  />
                  <label htmlFor="requireApproval" className="text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                    <span className="font-semibold block">Require Administrator Approval</span>
                    <span className="text-[11px] text-slate-500 dark:text-slate-400">
                      Devices will be held in pending status until approved before live telemetry ingestion.
                    </span>
                  </label>
                </div>

                <div className="mt-6 flex justify-end gap-2 pt-3 border-t border-slate-100 dark:border-slate-800">
                  <Button variant="ghost" onClick={() => setShowTokenModal(false)}>
                    Cancel
                  </Button>
                  <Button
                    onClick={() => tokenMutation.mutate()}
                    isLoading={tokenMutation.isPending}
                    icon={<KeyRound className="h-4 w-4" />}
                  >
                    Generate Enrollment Token
                  </Button>
                </div>
              </div>
            ) : (
              /* Token Display and Enrollment Commands */
              <div className="mt-5 space-y-4">
                <div className="flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3.5 py-2.5 text-xs text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                  <span>Enrollment token generated successfully! Valid until {new Date(generatedToken.expires_at).toLocaleString()}.</span>
                </div>

                {/* Raw Token Box */}
                <div className="rounded-xl border border-slate-200 bg-[#f8fafc] p-4 dark:border-slate-800 dark:bg-slate-900/80">
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      One-Time Enrollment Token
                    </label>
                    <span className="text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">Ready</span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <code className="text-xs font-mono text-[#0078d4] dark:text-blue-400 truncate flex-1 bg-white dark:bg-slate-800 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700">
                      {generatedToken.token}
                    </code>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => handleCopyText(generatedToken.token, false)}
                      icon={<Copy className="h-3.5 w-3.5" />}
                    >
                      {copiedToken ? "Copied!" : "Copy"}
                    </Button>
                  </div>
                </div>

                {/* Terminal Commands */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                      <Terminal className="h-3.5 w-3.5 text-[#0078d4]" />
                      Run on Target Endpoint:
                    </span>
                    <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 p-0.5 rounded-lg border border-slate-200 dark:border-slate-700">
                      <button
                        onClick={() => setSelectedOS("windows")}
                        className={`px-2.5 py-1 text-[11px] font-medium rounded-md transition-colors ${
                          selectedOS === "windows"
                            ? "bg-white dark:bg-[#131b2e] text-[#0078d4] dark:text-blue-400 shadow-xs"
                            : "text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
                        }`}
                      >
                        Windows (PowerShell)
                      </button>
                      <button
                        onClick={() => setSelectedOS("linux")}
                        className={`px-2.5 py-1 text-[11px] font-medium rounded-md transition-colors ${
                          selectedOS === "linux"
                            ? "bg-white dark:bg-[#131b2e] text-[#0078d4] dark:text-blue-400 shadow-xs"
                            : "text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
                        }`}
                      >
                        Linux / macOS
                      </button>
                    </div>
                  </div>

                  <div className="relative rounded-xl border border-slate-200 bg-[#0f172a] p-3 text-slate-200 font-mono text-[11px] dark:border-slate-800">
                    <pre className="overflow-x-auto whitespace-pre-wrap break-all pr-14 text-emerald-400">
                      {getCliCommand(generatedToken.token, selectedOS)}
                    </pre>
                    <button
                      onClick={() => handleCopyText(getCliCommand(generatedToken.token, selectedOS), true)}
                      className="absolute right-2.5 top-2.5 rounded-md bg-slate-800/90 p-1.5 text-slate-300 hover:bg-slate-700 hover:text-white transition-colors cursor-pointer border border-slate-700"
                      title="Copy full command"
                    >
                      {copiedCmd ? <span className="text-[10px] text-emerald-400 font-sans px-1">Copied!</span> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>

                  <div className="rounded-lg bg-slate-50 p-2.5 text-[11px] text-slate-600 dark:bg-slate-800/40 dark:text-slate-400 border border-slate-200 dark:border-slate-800">
                    <span className="font-semibold text-slate-800 dark:text-slate-200">Start Service Step:</span> After enrolling, run <code className="bg-slate-200 dark:bg-slate-700 px-1 py-0.5 rounded text-[#0078d4] dark:text-blue-400">python main.py --start</code> to begin live telemetry streaming.
                  </div>
                </div>

                <div className="mt-6 flex justify-between items-center pt-3 border-t border-slate-100 dark:border-slate-800">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setGeneratedToken(null);
                    }}
                  >
                    Generate Another
                  </Button>
                  <Button onClick={() => setShowTokenModal(false)}>
                    Done
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
