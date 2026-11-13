import React from "react";
import { clsx } from "clsx";

export interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => React.ReactNode;
  sortable?: boolean;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  isLoading?: boolean;
  onRowClick?: (item: T) => void;
  emptyMessage?: string;
}

export function DataTable<T extends { id?: string | number }>({
  columns,
  data,
  isLoading,
  onRowClick,
  emptyMessage = "No records found.",
}: DataTableProps<T>) {
  if (isLoading) {
    return (
      <div className="w-full overflow-hidden rounded-xl border border-slate-200 bg-white p-12 text-center dark:border-slate-800 dark:bg-[#131b2e]">
        <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-[#0078d4] border-t-transparent" />
        <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">Loading security records...</p>
      </div>
    );
  }

  return (
    <div className="w-full overflow-x-auto rounded-xl border border-slate-200 bg-white shadow-xs dark:border-slate-800 dark:bg-[#131b2e]">
      <table className="w-full border-collapse text-left text-xs md:text-sm">
        <thead>
          <tr className="border-b border-slate-200 bg-slate-50 text-[11px] font-semibold uppercase tracking-wider text-slate-600 dark:border-slate-800 dark:bg-slate-800/70 dark:text-slate-300">
            {columns.map((col) => (
              <th key={col.key} className={clsx("px-4 py-3.5", col.className)}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-normal">
          {data.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                className="px-4 py-12 text-center text-xs md:text-sm text-slate-500 dark:text-slate-400"
              >
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((item, idx) => (
              <tr
                key={(item.id as string) || idx}
                onClick={() => onRowClick && onRowClick(item)}
                className={clsx(
                  "transition-colors hover:bg-slate-50/80 dark:hover:bg-slate-800/40",
                  onRowClick && "cursor-pointer"
                )}
              >
                {columns.map((col) => (
                  <td key={col.key} className={clsx("px-4 py-3 text-slate-800 dark:text-slate-200", col.className)}>
                    {col.render ? col.render(item) : (item as any)[col.key]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
