import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Lock, User as UserIcon, KeyRound, CheckCircle2, Sun, Moon } from "lucide-react";
import { authService } from "../services/auth";
import { useAuthStore } from "../store/authStore";
import { useThemeStore } from "../store/themeStore";
import { Button } from "../components/ui/Button";
import { Input } from "../components/ui/Input";

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { setAuth } = useAuthStore();
  const { theme, toggleTheme } = useThemeStore();

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("SecureWatch@2026!");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await authService.login({
        username,
        password,
        mfa_code: mfaCode || undefined,
      });

      if (res.mfa_required) {
        setMfaRequired(true);
        setLoading(false);
        return;
      }

      if (res.tokens) {
        localStorage.setItem("access_token", res.tokens.access_token);
        localStorage.setItem("refresh_token", res.tokens.refresh_token);
        const me = await authService.getMe();
        setAuth(me, res.tokens.access_token, res.tokens.refresh_token);
        navigate("/dashboard");
      }
    } catch (err: any) {
      console.error("Login error:", err);
      const detail = err?.response?.data?.detail;
      if (detail) {
        setError(typeof detail === "string" ? detail : JSON.stringify(detail));
      } else if (err?.message) {
        setError(`Connection error: ${err.message}`);
      } else {
        setError("Invalid username or password");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-[#f4f6f8] dark:bg-[#0b0f19] p-4 text-slate-800 dark:text-slate-100 transition-colors duration-200">
      {/* Theme Switcher Top-Right */}
      <div className="absolute top-4 right-4">
        <button
          onClick={toggleTheme}
          title={`Switch to ${theme === "light" ? "Dark" : "Light"} Mode`}
          className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-xs hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 cursor-pointer transition-colors"
        >
          {theme === "light" ? (
            <>
              <Moon className="h-3.5 w-3.5 text-slate-600" />
              <span>Dark Mode</span>
            </>
          ) : (
            <>
              <Sun className="h-3.5 w-3.5 text-amber-400" />
              <span>Light Mode</span>
            </>
          )}
        </button>
      </div>

      <div className="relative w-full max-w-md rounded-2xl border border-slate-200 bg-white p-8 shadow-xl dark:border-slate-800 dark:bg-[#131b2e] dark:shadow-dark-card transition-all">
        {/* Defender Brand Header */}
        <div className="mb-6 text-center">
          <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-[#0078d4] text-white shadow-sm dark:shadow-dark-glow">
            <Shield className="h-6 w-6" />
          </div>
          <div className="flex items-center justify-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
              SecureWatch
            </h1>
            <span className="rounded-md bg-blue-50 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-[#0078d4] border border-blue-200 dark:border-blue-800 dark:bg-blue-950/60 dark:text-blue-400">
              Defender Portal
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            Enterprise Security Operations, EDR & IAM Platform
          </p>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="mb-5 rounded-xl border border-red-200 bg-red-50 p-3 text-xs text-red-700 dark:border-red-900/60 dark:bg-red-950/40 dark:text-red-300">
            {error}
          </div>
        )}

        {/* Default Credential Notice */}
        <div className="mb-5 flex items-center gap-2 rounded-xl border border-blue-200 bg-blue-50/70 px-3 py-2 text-xs text-blue-900 dark:border-blue-900/60 dark:bg-blue-950/40 dark:text-blue-300">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-[#0078d4] dark:text-blue-400" />
          <span>Administrative credentials pre-filled for instant verification.</span>
        </div>

        <form onSubmit={handleLogin} className="space-y-4">
          {!mfaRequired ? (
            <>
              <Input
                label="Username or Email"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
                icon={<UserIcon className="h-4 w-4" />}
              />
              <Input
                label="Password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                required
                icon={<Lock className="h-4 w-4" />}
              />
            </>
          ) : (
            <div>
              <p className="mb-3 text-xs text-[#0078d4] dark:text-blue-400">
                Multi-Factor Authentication (MFA) required. Enter the 6-digit verification code.
              </p>
              <Input
                label="6-Digit Authenticator Code"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456"
                maxLength={6}
                required
                autoFocus
                icon={<KeyRound className="h-4 w-4" />}
              />
            </div>
          )}

          <Button type="submit" isLoading={loading} className="w-full mt-2">
            {mfaRequired ? "Verify Code & Sign In" : "Sign In to Defender Console"}
          </Button>
        </form>

        {/* Security & Compliance Footer */}
        <div className="mt-6 border-t border-slate-100 dark:border-slate-800 pt-4 text-center">
          <p className="text-[11px] font-medium text-slate-500 dark:text-slate-400">
            FIPS 140-2 Validated • SOC 2 Type II • Enterprise RBAC
          </p>
          <p className="mt-0.5 text-[10px] text-slate-400 dark:text-slate-500">
            Authorized Personnel Only. Telemetry & Audit Logs Monitored.
          </p>
        </div>
      </div>
    </div>
  );
};
