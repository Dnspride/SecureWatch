import React, { useState, useEffect } from "react";
import { Settings, Shield, Sliders, Server, Save, Sun, Moon, Laptop, Palette, CheckCircle2 } from "lucide-react";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";
import { useThemeStore } from "../store/themeStore";
import api from "../services/api";

export const SettingsPage: React.FC = () => {
  const { theme, setTheme } = useThemeStore();

  // Settings form states
  const [lockoutThreshold, setLockoutThreshold] = useState("5");
  const [lockoutDuration, setLockoutDuration] = useState("15");
  const [minPasswordLength, setMinPasswordLength] = useState("12");
  const [heartbeatInterval, setHeartbeatInterval] = useState("60");
  const [offlineTimeout, setOfflineTimeout] = useState("300");
  const [retentionDays, setRetentionDays] = useState("90");

  const [savingIAM, setSavingIAM] = useState(false);
  const [savingTelemetry, setSavingTelemetry] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    api.get("/settings")
      .then((res) => {
        const d = res.data;
        if (d.account_lockout_threshold !== undefined) setLockoutThreshold(String(d.account_lockout_threshold));
        if (d.lockout_duration_minutes !== undefined) setLockoutDuration(String(d.lockout_duration_minutes));
        if (d.min_password_length !== undefined) setMinPasswordLength(String(d.min_password_length));
        if (d.agent_heartbeat_interval_seconds !== undefined) setHeartbeatInterval(String(d.agent_heartbeat_interval_seconds));
        if (d.offline_inactivity_timeout_seconds !== undefined) setOfflineTimeout(String(d.offline_inactivity_timeout_seconds));
        if (d.siem_event_retention_days !== undefined) setRetentionDays(String(d.siem_event_retention_days));
      })
      .catch(() => {});
  }, []);

  const handleSaveIAM = async () => {
    setSavingIAM(true);
    setSuccessMsg(null);
    try {
      await api.put("/settings", {
        account_lockout_threshold: Number(lockoutThreshold),
        lockout_duration_minutes: Number(lockoutDuration),
        min_password_length: Number(minPasswordLength),
        agent_heartbeat_interval_seconds: Number(heartbeatInterval),
        offline_inactivity_timeout_seconds: Number(offlineTimeout),
        siem_event_retention_days: Number(retentionDays),
      });
      setSuccessMsg("IAM and password policy thresholds updated successfully.");
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err: any) {
      console.error(err);
    } finally {
      setSavingIAM(false);
    }
  };

  const handleSaveTelemetry = async () => {
    setSavingTelemetry(true);
    setSuccessMsg(null);
    try {
      await api.put("/settings", {
        account_lockout_threshold: Number(lockoutThreshold),
        lockout_duration_minutes: Number(lockoutDuration),
        min_password_length: Number(minPasswordLength),
        agent_heartbeat_interval_seconds: Number(heartbeatInterval),
        offline_inactivity_timeout_seconds: Number(offlineTimeout),
        siem_event_retention_days: Number(retentionDays),
      });
      setSuccessMsg("Agent telemetry collection and log retention rules saved.");
      setTimeout(() => setSuccessMsg(null), 4000);
    } catch (err: any) {
      console.error(err);
    } finally {
      setSavingTelemetry(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
            Platform Security Settings
          </h1>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Configure IAM authentication lockout policies, telemetry collection thresholds, and console appearance.
          </p>
        </div>
        {successMsg && (
          <div className="flex items-center gap-2 rounded-xl bg-emerald-50 px-3.5 py-2 text-xs font-medium text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Appearance & Theme Selection Card */}
        <Card title="Console Theme & Appearance" subtitle="Choose between Enterprise Light and Dark SOC modes">
          <div className="space-y-4">
            <p className="text-xs text-slate-600 dark:text-slate-400">
              Select your preferred visual mode for the SecureWatch SOC console. All charts, tables, and telemetry monitors adapt seamlessly.
            </p>

            <div className="grid grid-cols-2 gap-4">
              <button
                type="button"
                onClick={() => setTheme("light")}
                className={`flex flex-col items-center justify-center p-4 rounded-xl border-2 transition-all cursor-pointer ${
                  theme === "light"
                    ? "border-[#0078d4] bg-blue-50/50 dark:bg-blue-950/30 text-[#0078d4] shadow-xs"
                    : "border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/60 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700"
                }`}
              >
                <Sun className="h-6 w-6 mb-2 text-amber-500" />
                <span className="text-sm font-semibold">Light Mode</span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Defender Clean White</span>
              </button>

              <button
                type="button"
                onClick={() => setTheme("dark")}
                className={`flex flex-col items-center justify-center p-4 rounded-xl border-2 transition-all cursor-pointer ${
                  theme === "dark"
                    ? "border-[#0078d4] bg-blue-50/50 dark:bg-blue-950/30 text-[#0078d4] shadow-xs"
                    : "border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/60 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-700"
                }`}
              >
                <Moon className="h-6 w-6 mb-2 text-blue-400" />
                <span className="text-sm font-semibold">Dark Mode</span>
                <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">CrowdStrike Deep SOC</span>
              </button>
            </div>
          </div>
        </Card>

        {/* IAM & Password Policies */}
        <Card title="IAM & Password Policies" subtitle="Authentication hardening and brute-force controls">
          <div className="space-y-4">
            <Input
              label="Account Lockout Failure Threshold"
              value={lockoutThreshold}
              onChange={(e) => setLockoutThreshold(e.target.value)}
              type="number"
            />
            <Input
              label="Temporary Lockout Duration (Minutes)"
              value={lockoutDuration}
              onChange={(e) => setLockoutDuration(e.target.value)}
              type="number"
            />
            <Input
              label="Minimum Password Complexity Length"
              value={minPasswordLength}
              onChange={(e) => setMinPasswordLength(e.target.value)}
              type="number"
            />
            <div className="pt-2">
              <Button
                size="sm"
                icon={<Save className="h-4 w-4" />}
                isLoading={savingIAM}
                onClick={handleSaveIAM}
              >
                Save IAM Policies
              </Button>
            </div>
          </div>
        </Card>

        {/* Agent Telemetry & Retention */}
        <Card title="Agent Telemetry & Retention" subtitle="Endpoint heartbeat frequencies and SIEM log lifecycle" className="lg:col-span-2">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Input
              label="Agent Heartbeat Interval (Seconds)"
              value={heartbeatInterval}
              onChange={(e) => setHeartbeatInterval(e.target.value)}
              type="number"
            />
            <Input
              label="Offline Inactivity Timeout (Seconds)"
              value={offlineTimeout}
              onChange={(e) => setOfflineTimeout(e.target.value)}
              type="number"
            />
            <Input
              label="OpenSearch SIEM Log Retention (Days)"
              value={retentionDays}
              onChange={(e) => setRetentionDays(e.target.value)}
              type="number"
            />
          </div>
          <div className="pt-4 flex justify-end">
            <Button
              size="sm"
              icon={<Save className="h-4 w-4" />}
              isLoading={savingTelemetry}
              onClick={handleSaveTelemetry}
            >
              Save Telemetry Settings
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
};
