import React, { useState } from "react";
import { FileText, Download, ShieldCheck, CheckCircle2, Clock } from "lucide-react";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";

export const ReportsPage: React.FC = () => {
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const reports = [
    {
      id: "1",
      title: "Executive Cybersecurity Posture Summary",
      type: "Executive Summary",
      created_at: new Date().toISOString(),
      size: "1.4 MB",
      format: "PDF",
    },
    {
      id: "2",
      title: "Endpoint Security & Host Compliance Audit",
      type: "Compliance",
      created_at: new Date().toISOString(),
      size: "3.2 MB",
      format: "PDF",
    },
    {
      id: "3",
      title: "MITRE ATT&CK Threat Detection Coverage",
      type: "SIEM Analysis",
      created_at: new Date().toISOString(),
      size: "850 KB",
      format: "PDF",
    },
  ];

  const handleDownload = (id: string, title: string) => {
    setDownloadingId(id);
    const token = localStorage.getItem("access_token");
    fetch(`/api/v1/reports/${id}/download`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then((res) => res.blob())
      .then((blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${title.toLowerCase().replace(/\s+/g, "_")}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      })
      .catch((err) => console.error("Download failed:", err))
      .finally(() => setDownloadingId(null));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Security Reports & Compliance Export
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Generate and export compliance audit evidence, risk assessments, and incident triage summaries.
          </p>
        </div>
        <Button icon={<FileText className="h-4 w-4" />}>
          Generate On-Demand Report
        </Button>
      </div>

      <div className="grid grid-cols-1 gap-4">
        {reports.map((r) => (
          <Card key={r.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4">
            <div className="flex items-center gap-3.5">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-[#0078d4] dark:bg-blue-950/60 dark:text-blue-400">
                <FileText className="h-5 w-5" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{r.title}</p>
                <div className="flex items-center gap-2 mt-0.5">
                  <Badge variant="neutral">{r.type}</Badge>
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    {r.size} • Generated {new Date(r.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              icon={<Download className="h-4 w-4" />}
              isLoading={downloadingId === r.id}
              onClick={() => handleDownload(r.id, r.title)}
            >
              Download {r.format}
            </Button>
          </Card>
        ))}
      </div>
    </div>
  );
};
