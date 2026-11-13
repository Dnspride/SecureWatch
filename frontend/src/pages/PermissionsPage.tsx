import React from "react";
import { useQuery } from "@tanstack/react-query";
import { KeyRound, Shield, RefreshCw } from "lucide-react";
import { roleService } from "../services/roles";
import { Card } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";

export const PermissionsPage: React.FC = () => {
  const { data: permissions = [], isLoading, refetch } = useQuery({
    queryKey: ["permissions"],
    queryFn: () => roleService.getPermissions(),
  });

  if (isLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#0078d4] border-t-transparent" />
      </div>
    );
  }

  // Group permissions by category
  const grouped = permissions.reduce((acc, p) => {
    acc[p.category] = acc[p.category] || [];
    acc[p.category].push(p);
    return acc;
  }, {} as Record<string, typeof permissions>);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Granular Permission Matrix
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Catalog of all API-enforced functional permissions enforced by backend RBAC middleware.
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

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {Object.entries(grouped).map(([category, perms]) => (
          <Card
            key={category}
            title={category.toUpperCase()}
            subtitle={`${perms.length} functional operations`}
          >
            <div className="divide-y divide-slate-100 dark:divide-slate-800/60">
              {perms.map((p) => (
                <div key={p.id} className="py-2.5 flex items-center justify-between">
                  <div>
                    <span className="font-mono text-xs font-semibold text-[#0078d4] dark:text-blue-400">
                      {p.code}
                    </span>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">{p.description}</p>
                  </div>
                  <Badge variant="neutral">{p.category}</Badge>
                </div>
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};
