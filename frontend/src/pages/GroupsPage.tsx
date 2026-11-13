import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { UsersRound, Plus, X, RefreshCw } from "lucide-react";
import { groupService } from "../services/groups";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";
import { Badge } from "../components/ui/Badge";

export const GroupsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [groupDept, setGroupDept] = useState("");
  const [groupDesc, setGroupDesc] = useState("");

  const { data: groups = [], isLoading, refetch } = useQuery({
    queryKey: ["groups"],
    queryFn: () => groupService.getGroups(),
  });

  const createMutation = useMutation({
    mutationFn: () =>
      groupService.createGroup({
        name: groupName,
        department: groupDept,
        description: groupDesc,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["groups"] });
      setShowCreateModal(false);
      setGroupName("");
      setGroupDept("");
      setGroupDesc("");
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
            Organizational Groups
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Group users by department, project, or access tier to inherit RBAC permissions.
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
            Create Group
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
        {groups.map((g) => (
          <Card key={g.id} className="p-5">
            <div className="flex items-center justify-between">
              <span className="text-base font-bold text-slate-900 dark:text-white">{g.name}</span>
              {g.department && <Badge variant="info">{g.department}</Badge>}
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{g.description || "No description provided."}</p>
            <div className="mt-4 flex items-center justify-between border-t border-slate-100 dark:border-slate-800 pt-3 text-xs text-slate-500 dark:text-slate-400">
              <span>{g.member_count} Members</span>
              <span>{g.role_count} Roles Assigned</span>
            </div>
          </Card>
        ))}
      </div>

      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl transition-all dark:border-slate-800 dark:bg-[#131b2e] dark:text-slate-100">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
              <h2 className="text-base font-bold text-slate-900 dark:text-white">Create Organizational Group</h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800 dark:hover:text-slate-200 cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="mt-4 space-y-3">
              <Input
                label="Group Name"
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
                placeholder="SOC Incident Responders"
                required
              />
              <Input
                label="Department"
                value={groupDept}
                onChange={(e) => setGroupDept(e.target.value)}
                placeholder="Security Operations"
              />
              <Input
                label="Description"
                value={groupDesc}
                onChange={(e) => setGroupDesc(e.target.value)}
                placeholder="Tier 2 analysts with elevated response permissions"
              />
            </div>
            <div className="mt-6 flex justify-end gap-2 border-t border-slate-100 dark:border-slate-800 pt-3">
              <Button variant="ghost" onClick={() => setShowCreateModal(false)}>
                Cancel
              </Button>
              <Button
                onClick={() => createMutation.mutate()}
                isLoading={createMutation.isPending}
              >
                Create Group
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
