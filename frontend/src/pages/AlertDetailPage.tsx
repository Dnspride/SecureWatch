import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  ShieldAlert,
  CheckCircle,
  XCircle,
  Clock,
  Laptop,
  MessageSquare,
  Send,
  RefreshCw,
} from "lucide-react";
import { alertService } from "../services/alerts";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";
import { RiskScore } from "../components/ui/RiskScore";
import { AlertStatus } from "../types";

export const AlertDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [noteContent, setNoteContent] = useState("");
  const [resolutionNotes, setResolutionNotes] = useState("");

  const { data: alert, isLoading, refetch } = useQuery({
    queryKey: ["alert", id],
    queryFn: () => alertService.getAlert(id!),
    enabled: !!id,
  });

  const updateStatusMutation = useMutation({
    mutationFn: (newStatus: AlertStatus) =>
      alertService.updateAlertStatus(id!, {
        status: newStatus,
        resolution_notes: resolutionNotes || undefined,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alert", id] }),
  });

  const addNoteMutation = useMutation({
    mutationFn: (content: string) => alertService.addNote(id!, { content }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert", id] });
      setNoteContent("");
    },
  });

  if (isLoading || !alert) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#0078d4] border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("/alerts")}
            icon={<ArrowLeft className="h-4 w-4" />}
          >
            Back
          </Button>
          <div>
            <div className="flex items-center gap-3">
              <Badge variant={alert.severity as any}>{alert.severity}</Badge>
              <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
                {alert.title}
              </h1>
            </div>
            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400 font-mono">
              Alert ID: {alert.id} • Detected: {new Date(alert.detection_time).toLocaleString()}
            </p>
          </div>
        </div>

        {/* Status Actions */}
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            icon={<RefreshCw className="h-3.5 w-3.5" />}
          >
            Refresh
          </Button>
          {alert.status === "new" && (
            <Button
              variant="outline"
              onClick={() => updateStatusMutation.mutate(AlertStatus.ACKNOWLEDGED)}
              isLoading={updateStatusMutation.isPending}
            >
              Acknowledge
            </Button>
          )}

          {alert.status !== "resolved" && (
            <Button
              variant="primary"
              onClick={() => updateStatusMutation.mutate(AlertStatus.RESOLVED)}
              isLoading={updateStatusMutation.isPending}
              icon={<CheckCircle className="h-4 w-4" />}
            >
              Resolve Alert
            </Button>
          )}

          {alert.status !== "false_positive" && (
            <Button
              variant="danger"
              onClick={() => updateStatusMutation.mutate(AlertStatus.FALSE_POSITIVE)}
              isLoading={updateStatusMutation.isPending}
            >
              Mark False Positive
            </Button>
          )}
        </div>
      </div>

      {/* Main Details Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left 2 Cols: Details & Investigation steps */}
        <div className="space-y-6 lg:col-span-2">
          <Card title="Alert Description">
            <p className="text-sm text-slate-800 dark:text-slate-200 leading-relaxed">
              {alert.description || "Security event triggered a threshold violation."}
            </p>
          </Card>

          <Card title="Recommended SOC Investigation Steps">
            <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
              {alert.recommended_steps?.map((step, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-blue-500/10 text-[#0078d4] dark:bg-blue-950/60 dark:text-blue-400 font-bold">
                    {idx + 1}
                  </span>
                  <span>{step}</span>
                </li>
              )) || <li>Perform standard endpoint triage and review recent process launches.</li>}
            </ul>
          </Card>

          {/* Investigation Notes Thread */}
          <Card
            title="Analyst Investigation Notes"
            subtitle="Record forensic observations and triage hypotheses"
          >
            <div className="space-y-4">
              <div className="max-h-60 overflow-y-auto space-y-3">
                {alert.notes?.length === 0 ? (
                  <p className="text-xs text-slate-400 dark:text-slate-500 py-2">No analyst notes recorded yet.</p>
                ) : (
                  alert.notes?.map((n) => (
                    <div
                      key={n.id}
                      className="rounded-xl border border-slate-200 bg-[#f4f6f8]/60 p-3 dark:border-slate-800 dark:bg-slate-900/60"
                    >
                      <div className="flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400 mb-1">
                        <span className="font-semibold text-[#0078d4] dark:text-blue-400">{n.author_name}</span>
                        <span>{new Date(n.created_at).toLocaleTimeString()}</span>
                      </div>
                      <p className="text-xs text-slate-800 dark:text-slate-200">{n.content}</p>
                    </div>
                  ))
                )}
              </div>

              {/* Add Note Form */}
              <div className="flex gap-2">
                <input
                  type="text"
                  value={noteContent}
                  onChange={(e) => setNoteContent(e.target.value)}
                  placeholder="Enter analyst observation..."
                  className="flex-1 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-800 placeholder-slate-400 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500 focus:border-[#0078d4] focus:outline-none"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && noteContent.trim()) {
                      addNoteMutation.mutate(noteContent.trim());
                    }
                  }}
                />
                <Button
                  size="sm"
                  onClick={() => noteContent.trim() && addNoteMutation.mutate(noteContent.trim())}
                  isLoading={addNoteMutation.isPending}
                  icon={<Send className="h-3.5 w-3.5" />}
                >
                  Add
                </Button>
              </div>
            </div>
          </Card>
        </div>

        {/* Right Column: Context & Metadata */}
        <div className="space-y-6">
          <Card title="Context Attributes">
            <div className="space-y-3 text-xs">
              <div className="flex justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
                <span className="text-slate-500 dark:text-slate-400">Target Device:</span>
                <span className="font-semibold text-[#0078d4] dark:text-blue-400">{alert.device_name || "—"}</span>
              </div>
              <div className="flex justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
                <span className="text-slate-500 dark:text-slate-400">Status:</span>
                <Badge variant={alert.status === "new" ? "critical" : alert.status === "resolved" ? "success" : "info"}>
                  {alert.status}
                </Badge>
              </div>
              <div className="flex justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
                <span className="text-slate-500 dark:text-slate-400">Risk Contribution:</span>
                <RiskScore score={alert.risk_score} size="sm" />
              </div>
              <div className="flex justify-between border-b border-slate-100 dark:border-slate-800 pb-2">
                <span className="text-slate-500 dark:text-slate-400">Assigned Analyst:</span>
                <span className="text-slate-800 dark:text-slate-200">{alert.assigned_to_name || "Unassigned"}</span>
              </div>
            </div>
          </Card>

          {alert.resolution_notes && (
            <Card title="Resolution Notes">
              <p className="text-xs text-emerald-600 dark:text-emerald-400">{alert.resolution_notes}</p>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};
