import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus, Search, Lock, Unlock, Trash2, Key, X, RefreshCw } from "lucide-react";
import { userService } from "../services/users";
import { roleService } from "../services/roles";
import { User } from "../types";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";
import { Badge } from "../components/ui/Badge";
import { DataTable, Column } from "../components/ui/DataTable";

export const UsersPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [showCreateModal, setShowCreateModal] = useState(false);

  // New user form state
  const [newUsername, setNewUsername] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newFullName, setNewFullName] = useState("");
  const [newDepartment, setNewDepartment] = useState("Security Operations");
  const [newPassword, setNewPassword] = useState("");
  const [selectedRoleIds, setSelectedRoleIds] = useState<string[]>([]);
  const [formError, setFormError] = useState<string | null>(null);

  // 1. Fetch Users
  const { data: usersData, isLoading, refetch } = useQuery({
    queryKey: ["users", search, page],
    queryFn: () => userService.getUsers({ search, page, page_size: 15 }),
  });

  // 2. Fetch Roles for dropdown
  const { data: roles = [] } = useQuery({
    queryKey: ["roles"],
    queryFn: () => roleService.getRoles(),
  });

  // 3. Mutations
  const createMutation = useMutation({
    mutationFn: userService.createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setShowCreateModal(false);
      // Reset form
      setNewUsername("");
      setNewEmail("");
      setNewFullName("");
      setNewPassword("");
      setSelectedRoleIds([]);
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err?.response?.data?.detail || "Failed to create user");
    },
  });

  const lockMutation = useMutation({
    mutationFn: (id: string) => userService.lockUser(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  const unlockMutation = useMutation({
    mutationFn: (id: string) => userService.unlockUser(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => userService.deleteUser(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["users"] }),
  });

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    createMutation.mutate({
      username: newUsername,
      email: newEmail,
      full_name: newFullName,
      department: newDepartment,
      password: newPassword,
      role_ids: selectedRoleIds,
      is_active: true,
      is_superuser: false,
    });
  };

  const columns: Column<User>[] = [
    {
      key: "user",
      header: "User Identity",
      render: (u) => (
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-50 text-[#0078d4] dark:bg-blue-950/60 dark:text-blue-400 font-bold text-xs">
            {u.full_name ? u.full_name[0] : u.username[0]}
          </div>
          <div>
            <p className="font-semibold text-slate-900 dark:text-slate-100">{u.full_name}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">@{u.username}</p>
          </div>
        </div>
      ),
    },
    { key: "email", header: "Email Address" },
    {
      key: "department",
      header: "Department",
      render: (u) => (
        <span className="text-xs text-slate-700 dark:text-slate-300 font-medium">{u.department || "—"}</span>
      ),
    },
    {
      key: "roles",
      header: "Assigned Roles",
      render: (u) => (
        <div className="flex flex-wrap gap-1">
          {u.roles?.map((r) => (
            <Badge key={r.id} variant="info">
              {r.name}
            </Badge>
          )) || <span className="text-xs text-slate-400 dark:text-slate-500">None</span>}
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (u) => (
        <Badge variant={u.is_locked ? "critical" : u.is_active ? "success" : "neutral"}>
          {u.is_locked ? "Locked" : u.is_active ? "Active" : "Inactive"}
        </Badge>
      ),
    },
    {
      key: "mfa",
      header: "2FA",
      render: (u) => (
        <Badge variant={u.mfa_enabled ? "success" : "neutral"}>
          {u.mfa_enabled ? "Enabled" : "Disabled"}
        </Badge>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      className: "text-right",
      render: (u) => (
        <div className="flex items-center justify-end gap-2">
          {u.is_locked ? (
            <button
              onClick={() => unlockMutation.mutate(u.id)}
              title="Unlock Account"
              className="rounded-lg p-1.5 text-amber-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <Unlock className="h-4 w-4" />
            </button>
          ) : (
            <button
              onClick={() => lockMutation.mutate(u.id)}
              title="Lock Account"
              className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-amber-500 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-amber-400 transition-colors cursor-pointer"
            >
              <Lock className="h-4 w-4" />
            </button>
          )}

          {!u.is_superuser && (
            <button
              onClick={() => {
                if (window.confirm(`Delete user ${u.username}?`)) {
                  deleteMutation.mutate(u.id);
                }
              }}
              title="Delete Account"
              className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100 hover:text-red-500 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-red-400 transition-colors cursor-pointer"
            >
              <Trash2 className="h-4 w-4" />
            </button>
          )}
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
            Identity & Access Management (IAM)
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Manage user accounts, RBAC memberships, authentication status, and 2FA.
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
            onClick={() => setShowCreateModal(true)}
            icon={<UserPlus className="h-4 w-4" />}
          >
            Create User
          </Button>
        </div>
      </div>

      {/* Filter / Search Bar */}
      <div className="flex items-center justify-between gap-4">
        <div className="relative w-80">
          <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name, username, or email..."
            className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-10 pr-4 text-xs text-slate-800 placeholder-slate-400 dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100 dark:placeholder-slate-500 focus:border-[#0078d4] focus:outline-none focus:ring-1 focus:ring-[#0078d4]"
          />
        </div>
      </div>

      {/* Users DataTable */}
      <DataTable
        columns={columns}
        data={usersData?.items || []}
        isLoading={isLoading}
        emptyMessage="No users found matching query."
      />

      {/* Create User Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl transition-all dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-white">Create New User</h2>
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  Provision a new user account with secure credentials and RBAC assignment.
                </p>
              </div>
              <button
                onClick={() => setShowCreateModal(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {formError && (
              <div className="mt-4 rounded-xl border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-500 dark:text-red-400">
                {formError}
              </div>
            )}

            <form onSubmit={handleCreateSubmit} className="mt-4 space-y-3">
              <Input
                label="Full Name"
                value={newFullName}
                onChange={(e) => setNewFullName(e.target.value)}
                placeholder="Jane Doe"
                required
              />
              <Input
                label="Username"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="jdoe"
                required
              />
              <Input
                label="Email"
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                placeholder="jdoe@company.com"
                required
              />
              <Input
                label="Department"
                value={newDepartment}
                onChange={(e) => setNewDepartment(e.target.value)}
                placeholder="Security Operations"
              />
              <Input
                label="Password (min 12 chars, upper, lower, digit, symbol)"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="••••••••••••"
                required
              />

              {/* Roles selection */}
              <div>
                <label className="mb-1 block text-xs font-semibold text-slate-700 dark:text-slate-300">
                  Assign Roles
                </label>
                <div className="max-h-32 overflow-y-auto space-y-1 rounded-xl border border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-900/60 p-2.5">
                  {roles.map((r) => (
                    <label key={r.id} className="flex items-center gap-2 text-xs text-slate-800 dark:text-slate-200 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedRoleIds.includes(r.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedRoleIds([...selectedRoleIds, r.id]);
                          } else {
                            setSelectedRoleIds(selectedRoleIds.filter((id) => id !== r.id));
                          }
                        }}
                        className="rounded border-slate-300 text-[#0078d4] focus:ring-[#0078d4] dark:border-slate-700 dark:bg-slate-800"
                      />
                      <span>{r.name}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="mt-6 flex justify-end gap-2 pt-3 border-t border-slate-100 dark:border-slate-800">
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => setShowCreateModal(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" isLoading={createMutation.isPending}>
                  Create User
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
