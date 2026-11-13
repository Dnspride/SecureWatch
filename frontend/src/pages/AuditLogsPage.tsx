import React, { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { History, ShieldCheck, Search, CheckCircle2, AlertCircle, RefreshCw } from "lucide-react";
import { auditService } from "../services/audit";
import { AuditLog } from "../types";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";
import { DataTable, Column } from "../components/ui/DataTable";

export const AuditLogsPage: React.FC = () => {
  const [actorFilter, setActorFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [verificationResult, setVerificationResult] = useState<{
    success: boolean;
    message: string;
  } | null>(null);

  const { data: auditData, isLoading, refetch } = useQuery({
    queryKey: ["audit-logs", actorFilter, actionFilter],
    queryFn: () =>
      auditService.getAuditLogs({
        actor_username: actorFilter || undefined,
        action: actionFilter || undefined,
        page_size: 50,
      }),
  });

  const verifyMutation = useMutation({
    mutationFn: () => auditService.verifyIntegrity(1000),
    onSuccess: (res) => {
      setVerificationResult(res);
    },
    onError: (err: any) => {
      setVerificationResult({
        success: false,
        message: err?.response?.data?.detail || "Integrity verification failed",
      });
    },
  });

  const columns: Column<AuditLog>[] = [
    {
      key: "time",
      header: "Timestamp",
      render: (log) => (
        <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
          {new Date(log.timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      key: "actor",
      header: "Actor",
      render: (log) => (
        <span className="font-semibold text-[#0078d4] dark:text-blue-400">
          {log.actor_username || "System"}
        </span>
      ),
    },
    {
      key: "action",
      header: "Action",
      render: (log) => (
        <span className="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-mono text-slate-800 dark:bg-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700">
          {log.action}
        </span>
      ),
    },
    {
      key: "resource",
      header: "Target Resource",
      render: (log) => (
        <span className="text-xs text-slate-700 dark:text-slate-300 font-mono">
          {log.resource_type}:{log.resource_id || "—"}
        </span>
      ),
    },
    {
      key: "result",
      header: "Result",
      render: (log) => (
        <Badge variant={log.result === "success" ? "success" : "critical"}>
          {log.result}
        </Badge>
      ),
    },
    {
      key: "hash",
      header: "SHA-256 Hash Chain",
      render: (log) => (
        <span className="font-mono text-[11px] text-slate-400 dark:text-slate-500 truncate block max-w-xs" title={log.hash}>
          {log.hash.slice(0, 16)}...
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Audit Trail & Cryptographic Verification
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Immutable, append-only log of all security mutations linked by cryptographic hash chaining.
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
            variant="outline"
            onClick={() => verifyMutation.mutate()}
            isLoading={verifyMutation.isPending}
            icon={<ShieldCheck className="h-4 w-4" />}
          >
            Verify Chain Integrity
          </Button>
        </div>
      </div>

      {/* Verification Notice Banner */}
      {verificationResult && (
        <div
          className={`flex items-center gap-3 rounded-xl border p-4 text-xs font-semibold ${
            verificationResult.success
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
              : "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400"
          }`}
        >
          {verificationResult.success ? (
            <CheckCircle2 className="h-5 w-5 shrink-0" />
          ) : (
            <AlertCircle className="h-5 w-5 shrink-0" />
          )}
          <span>{verificationResult.message}</span>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="relative w-80">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            placeholder="Filter by actor username..."
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-10 pr-4 text-xs text-slate-800 placeholder-slate-400 dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 dark:placeholder-slate-500 focus:border-[#0078d4] focus:outline-none focus:ring-1 focus:ring-[#0078d4]"
          />
        </div>
      </div>

      {/* Audit DataTable */}
      <DataTable
        columns={columns}
        data={auditData?.items || []}
        isLoading={isLoading}
        emptyMessage="No audit records found."
      />
    </div>
  );
};
