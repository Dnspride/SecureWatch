import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, Plus, Check, X, RefreshCw } from "lucide-react";
import { roleService } from "../services/roles";
import { Role } from "../types";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Badge } from "../components/ui/Badge";
import { Input } from "../components/ui/Input";

export const RolesPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [roleName, setRoleName] = useState("");
  const [roleDesc, setRoleDesc] = useState("");
  const [selectedPerms, setSelectedPerms] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const { data: roles = [], isLoading, refetch } = useQuery({
    queryKey: ["roles"],
    queryFn: () => roleService.getRoles(),
  });

  const { data: permissions = [] } = useQuery({
    queryKey: ["permissions"],
    queryFn: () => roleService.getPermissions(),
  });

  const createMutation = useMutation({
    mutationFn: () =>
      roleService.createRole({
        name: roleName,
        description: roleDesc,
        permission_ids: selectedPerms,
        is_active: true,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["roles"] });
      setShowCreateModal(false);
      setRoleName("");
      setRoleDesc("");
      setSelectedPerms([]);
      setError(null);
    },
    onError: (err: any) => {
      setError(err?.response?.data?.detail || "Failed to create role");
    },
  });

  if (isLoading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#0078d4] border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Role-Based Access Control (RBAC)
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Configure system roles, access policies, and granular operational permissions.
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
          <Button onClick={() => setShowCreateModal(true)} icon={<Plus className="h-4 w-4" />}>
            Create Custom Role
          </Button>
        </div>
      </div>

      {/* Role Cards Grid */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {roles.map((r) => (
          <Card key={r.id} className="flex flex-col justify-between p-5">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-base font-bold text-slate-900 dark:text-white">{r.name}</span>
                {r.is_system_role && <Badge variant="info">Predefined</Badge>}
              </div>
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{r.description || "Custom role"}</p>

              <div className="mt-4 border-t border-slate-100 dark:border-slate-800 pt-3">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                  Permissions ({r.permissions?.length || 0}):
                </p>
                <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                  {r.permissions?.map((p) => (
                    <span
                      key={p.id}
                      className="rounded-md bg-slate-100 px-2 py-0.5 text-[11px] font-mono text-[#0078d4] dark:bg-slate-800 dark:text-blue-300 border border-slate-200 dark:border-slate-700"
                    >
                      {p.code}
                    </span>
                  )) || <span className="text-xs text-slate-400 dark:text-slate-500">None</span>}
                </div>
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* Create Role Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl transition-all dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-white">Create Custom RBAC Role</h2>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  Define a tailored security role with granular platform permissions.
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {error && (
              <div className="mt-3 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-500 dark:text-red-400">
                {error}
              </div>
            )}

            <div className="mt-4 space-y-3">
              <Input
                label="Role Name"
                value={roleName}
                onChange={(e) => setRoleName(e.target.value)}
                placeholder="Tier 1 Incident Responder"
                required
              />
              <Input
                label="Description"
                value={roleDesc}
                onChange={(e) => setRoleDesc(e.target.value)}
                placeholder="Can view devices and triage alerts"
              />

              <div>
                <label className="mb-1 block text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Select Permissions
                </label>
                <div className="max-h-48 overflow-y-auto space-y-1.5 rounded-xl border border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-900/60 p-3">
                  {permissions.map((p) => (
                    <label key={p.id} className="flex items-center gap-2 text-xs text-slate-800 dark:text-slate-200 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedPerms.includes(p.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedPerms([...selectedPerms, p.id]);
                          } else {
                            setSelectedPerms(selectedPerms.filter((id) => id !== p.id));
                          }
                        }}
                        className="rounded border-slate-300 text-[#0078d4] focus:ring-[#0078d4] dark:border-slate-700 dark:bg-slate-800"
                      />
                      <span className="font-mono text-[#0078d4] dark:text-blue-400">{p.code}</span>
                      <span className="text-slate-500 dark:text-slate-400 truncate">({p.name})</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-2 pt-3 border-t border-slate-100 dark:border-slate-800">
              <Button variant="ghost" onClick={() => setShowCreateModal(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate()}
                isLoading={createMutation.isPending}
              >
                Save Role
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
