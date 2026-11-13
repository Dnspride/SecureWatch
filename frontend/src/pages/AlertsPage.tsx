import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { AlertTriangle, CheckCircle, Search, Shield, UserCheck, RefreshCw } from "lucide-react";
import { alertService } from "../services/alerts";
import { Alert } from "../types";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";
import { RiskScore } from "../components/ui/RiskScore";
import { DataTable, Column } from "../components/ui/DataTable";

export const AlertsPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [page, setPage] = useState(1);

  const { data: alertsData, isLoading, refetch } = useQuery({
    queryKey: ["alerts", severityFilter, statusFilter, page],
    queryFn: () =>
      alertService.getAlerts({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        page,
        page_size: 25,
      }),
  });

  const ackMutation = useMutation({
    mutationFn: (id: string) => alertService.acknowledgeAlert(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });

  const columns: Column<Alert>[] = [
    {
      key: "time",
      header: "Detected",
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
    {
      key: "title",
      header: "Alert Title",
      render: (a) => (
        <div>
          <p className="font-semibold text-slate-900 hover:text-[#0078d4] dark:text-slate-100 dark:hover:text-blue-400 transition-colors">
            {a.title}
          </p>
          <p className="text-xs text-slate-400 dark:text-slate-500 truncate max-w-md">{a.description}</p>
        </div>
      ),
    },
    {
      key: "device",
      header: "Target Endpoint",
      render: (a) => (
        <span className="text-xs font-semibold text-[#0078d4] dark:text-blue-400">
          {a.device_name || "—"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (a) => (
        <Badge
          variant={
            a.status === "new"
              ? "critical"
              : a.status === "resolved"
              ? "success"
              : "info"
          }
        >
          {a.status}
        </Badge>
      ),
    },
    {
      key: "risk",
      header: "Risk",
      render: (a) => <RiskScore score={a.risk_score} size="sm" />,
    },
    {
      key: "actions",
      header: "Quick Action",
      className: "text-right",
      render: (a) => (
        <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          {a.status === "new" && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => ackMutation.mutate(a.id)}
              isLoading={ackMutation.isPending}
            >
              Acknowledge
            </Button>
          )}
          <Button
            size="sm"
            variant="secondary"
            onClick={() => navigate(`/alerts/${a.id}`)}
          >
            Investigate
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Threat Detection & Alerts
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Correlated security detections matched against MITRE ATT&CK enterprise detection rules.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          icon={<RefreshCw className="h-3.5 w-3.5" />}
        >
          Refresh
        </Button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs text-slate-800 transition-colors dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 focus:border-[#0078d4] focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs text-slate-800 transition-colors dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 focus:border-[#0078d4] focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="new">New (Unacknowledged)</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>

      {/* Alerts DataTable */}
      <DataTable
        columns={columns}
        data={alertsData?.items || []}
        isLoading={isLoading}
        onRowClick={(a) => navigate(`/alerts/${a.id}`)}
        emptyMessage="No security alerts found matching filter."
      />
    </div>
  );
};
