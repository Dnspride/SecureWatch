import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Laptop,
  ArrowLeft,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Activity,
  Network,
  FileCode,
  Lock,
  RotateCcw,
  RefreshCw,
} from "lucide-react";
import { deviceService } from "../services/devices";
import { eventService } from "../services/events";
import { alertService } from "../services/alerts";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";
import { StatusDot } from "../components/ui/StatusDot";
import { RiskScore } from "../components/ui/RiskScore";
import { DataTable, Column } from "../components/ui/DataTable";
import { SecurityEvent, Alert } from "../types";

export const DeviceDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"auth" | "process" | "network" | "fim" | "alerts">("auth");

  // 1. Fetch Device Record
  const { data: device, isLoading: deviceLoading, refetch } = useQuery({
    queryKey: ["device", id],
    queryFn: () => deviceService.getDevice(id!),
    enabled: !!id,
  });

  // 2. Fetch Events for this device
  const { data: eventsData } = useQuery({
    queryKey: ["device-events", id, activeTab],
    queryFn: () =>
      eventService.searchEvents({
        device_id: id,
        event_category: activeTab === "alerts" ? undefined : activeTab,
        page_size: 50,
      }),
    enabled: !!id && activeTab !== "alerts",
  });

  // 3. Fetch Alerts for this device
  const { data: alertsData } = useQuery({
    queryKey: ["device-alerts", id],
    queryFn: () =>
      alertService.getAlerts({
        device_id: id,
        page_size: 50,
      }),
    enabled: !!id && activeTab === "alerts",
  });

  // 4. Mutations
  const approveMutation = useMutation({
    mutationFn: () => deviceService.approveDevice(id!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["device", id] }),
  });

  const revokeMutation = useMutation({
    mutationFn: () => deviceService.revokeDevice(id!, "Administrative quarantine"),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["device", id] }),
  });

  if (deviceLoading || !device) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#0078d4] border-t-transparent" />
      </div>
    );
  }

  const eventColumns: Column<SecurityEvent>[] = [
    {
      key: "time",
      header: "Timestamp",
      render: (e) => (
        <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
          {new Date(e.event_timestamp).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      render: (e) => <Badge variant={e.severity as any}>{e.severity}</Badge>,
    },
    { key: "event_type", header: "Event Type" },
    {
      key: "process",
      header: "Process / File",
      render: (e) => (
        <span className="font-mono text-xs text-slate-700 dark:text-slate-300">
          {e.process_name || e.file_path || "—"}
        </span>
      ),
    },
    {
      key: "network",
      header: "Network",
      render: (e) => (
        <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
          {e.source_ip ? `${e.source_ip} -> ${e.destination_ip || ""}` : "—"}
        </span>
      ),
    },
    { key: "event_description", header: "Description" },
  ];

  const alertColumns: Column<Alert>[] = [
    {
      key: "time",
      header: "Detected At",
      render: (a) => (
        <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
          {new Date(a.detection_time).toLocaleTimeString()}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      render: (a) => <Badge variant={a.severity as any}>{a.severity}</Badge>,
    },
    { key: "title", header: "Alert Title" },
    {
      key: "status",
      header: "Status",
      render: (a) => (
        <Badge variant={a.status === "new" ? "critical" : a.status === "resolved" ? "success" : "info"}>
          {a.status}
        </Badge>
      ),
    },
    {
      key: "actions",
      header: "Action",
      render: (a) => (
        <Button size="sm" variant="secondary" onClick={() => navigate(`/alerts/${a.id}`)}>
          Triage
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Back button & Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("/devices")}
            icon={<ArrowLeft className="h-4 w-4" />}
          >
            Back
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                {device.hostname}
              </h1>
              <StatusDot status={device.status as any} label={device.status} />
            </div>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400 font-mono">
              Device ID: {device.id}
            </p>
          </div>
        </div>

        {/* Remote Action Controls */}
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            Refresh
          </Button>
          {device.status === "pending_approval" && (
            <Button
              onClick={() => approveMutation.mutate()}
              isLoading={approveMutation.isPending}
            >
              Approve Enrollment
            </Button>
          )}

          {device.status !== "revoked" ? (
            <Button
              variant="danger"
              onClick={() => {
                if (window.confirm("Quarantine this device and revoke all API communications?")) {
                  revokeMutation.mutate();
                }
              }}
              isLoading={revokeMutation.isPending}
            >
              Quarantine Device
            </Button>
          ) : (
            <span className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-bold text-red-500 dark:text-red-400">
              REVOKED & QUARANTINED
            </span>
          )}
        </div>
      </div>

      {/* Device Overview Card */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400">Hardware & OS</span>
          <p className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">
            {device.os_name} {device.os_version}
          </p>
          <p className="text-xs text-slate-400 dark:text-slate-500">Arch: {device.os_arch}</p>
        </Card>

        <Card className="p-4">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400">Network Interfaces</span>
          <p className="mt-2 text-sm font-mono text-slate-900 dark:text-white">
            {device.private_ip || "127.0.0.1"}
          </p>
          <p className="text-xs text-slate-400 dark:text-slate-500">MAC: {device.mac_address || "—"}</p>
        </Card>

        <Card className="p-4">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400">Agent Telemetry</span>
          <p className="mt-2 text-sm text-slate-900 dark:text-white">
            Agent: <span className="font-mono text-[#0078d4] dark:text-blue-400">v{device.agent_version || "1.0.0"}</span>
          </p>
          <p className="text-xs text-slate-400 dark:text-slate-500">
            Heartbeat: {device.last_heartbeat ? new Date(device.last_heartbeat).toLocaleTimeString() : "—"}
          </p>
        </Card>

        <Card className="p-4 flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-slate-500 dark:text-slate-400">Risk Assessment</span>
            <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">Host Risk Index</p>
          </div>
          <RiskScore score={device.risk_score} size="lg" />
        </Card>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-800">
        <div className="flex gap-4">
          {[
            { id: "auth", label: "Authentication" },
            { id: "process", label: "Process Monitor" },
            { id: "network", label: "Network Metadata" },
            { id: "fim", label: "File Integrity (FIM)" },
            { id: "alerts", label: "Triggered Alerts" },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setActiveTab(t.id as any)}
              className={`pb-3 text-sm font-semibold transition-colors border-b-2 cursor-pointer ${
                activeTab === t.id
                  ? "border-[#0078d4] text-[#0078d4] dark:border-blue-400 dark:text-blue-400"
                  : "border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Data Table */}
      {activeTab === "alerts" ? (
        <DataTable
          columns={alertColumns}
          data={alertsData?.items || []}
          emptyMessage="No security alerts generated for this device."
        />
      ) : (
        <DataTable
          columns={eventColumns}
          data={eventsData?.items || []}
          emptyMessage={`No ${activeTab} events recorded from this endpoint.`}
        />
      )}
    </div>
  );
};
