import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Filter, Download, Activity, Eye, X, RefreshCw } from "lucide-react";
import { eventService } from "../services/events";
import { SecurityEvent } from "../types";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";
import { DataTable, Column } from "../components/ui/DataTable";

export const SecurityEventsPage: React.FC = () => {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const { data: eventsData, isLoading, refetch } = useQuery({
    queryKey: ["security-events", query, category, severity, page],
    queryFn: () =>
      eventService.searchEvents({
        query: query || undefined,
        event_category: category || undefined,
        severity: severity || undefined,
        page,
        page_size: 50,
      }),
  });

  const columns: Column<SecurityEvent>[] = [
    {
      key: "time",
      header: "Timestamp",
      render: (e) => (
        <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
          {new Date(e.event_timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      render: (e) => <Badge variant={e.severity as any}>{e.severity}</Badge>,
    },
    {
      key: "category",
      header: "Category",
      render: (e) => (
        <span className="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-mono text-[#0078d4] dark:bg-slate-800 dark:text-blue-400 border border-slate-200 dark:border-slate-700 capitalize">
          {e.event_category}
        </span>
      ),
    },
    {
      key: "event_type",
      header: "Event Type",
      render: (e) => <span className="font-medium text-slate-900 dark:text-slate-100">{e.event_type}</span>,
    },
    {
      key: "source_ip",
      header: "Source IP",
      render: (e) => (
        <span className="font-mono text-xs text-slate-700 dark:text-slate-300">{e.source_ip || "—"}</span>
      ),
    },
    {
      key: "process",
      header: "Process / Target",
      render: (e) => (
        <span className="font-mono text-xs text-slate-700 dark:text-slate-300">
          {e.process_name || e.file_path || "—"}
        </span>
      ),
    },
    {
      key: "event_description",
      header: "Description",
      render: (e) => <span className="text-slate-600 dark:text-slate-400 truncate max-w-xs">{e.event_description}</span>,
    },
    {
      key: "actions",
      header: "Details",
      className: "text-right",
      render: (e) => (
        <button
          onClick={(ev) => {
            ev.stopPropagation();
            setSelectedEvent(e);
          }}
          className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-[#0078d4] dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-blue-400 transition-colors cursor-pointer"
        >
          <Eye className="h-4 w-4" />
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            SIEM Security Events
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Search and analyze normalized telemetry collected across all enterprise endpoints.
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
        <div className="relative w-80">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search keywords, processes, IPs..."
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-10 pr-4 text-xs text-slate-800 placeholder-slate-400 dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 dark:placeholder-slate-500 focus:border-[#0078d4] focus:outline-none focus:ring-1 focus:ring-[#0078d4]"
          />
        </div>

        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs text-slate-800 transition-colors dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 focus:border-[#0078d4] focus:outline-none"
        >
          <option value="">All Categories</option>
          <option value="authentication">Authentication</option>
          <option value="process">Process Creation</option>
          <option value="network">Network Connections</option>
          <option value="fim">File Integrity (FIM)</option>
          <option value="system_posture">System Posture</option>
        </select>

        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-xl border border-slate-200 bg-white px-3.5 py-2 text-xs text-slate-800 transition-colors dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 focus:border-[#0078d4] focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
      </div>

      {/* Events DataTable */}
      <DataTable
        columns={columns}
        data={eventsData?.items || []}
        isLoading={isLoading}
        onRowClick={(e) => setSelectedEvent(e)}
        emptyMessage="No security events matching query."
      />

      {/* Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl transition-all dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3 dark:border-slate-800">
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                  {selectedEvent.event_type}
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Source: {selectedEvent.event_source} • {new Date(selectedEvent.event_timestamp).toISOString()}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant={selectedEvent.severity as any}>
                  {selectedEvent.severity}
                </Badge>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400">Description:</p>
                <p className="text-sm text-slate-800 dark:text-slate-200">{selectedEvent.event_description}</p>
              </div>

              <div>
                <p className="text-xs font-semibold text-slate-500 dark:text-slate-400">Raw Normalized Event JSON:</p>
                <pre className="max-h-60 overflow-y-auto rounded-xl bg-[#f4f6f8] p-3 text-xs font-mono text-blue-700 dark:bg-slate-900 dark:text-blue-300 border border-slate-200 dark:border-slate-800">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <Button onClick={() => setSelectedEvent(null)}>Close</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
