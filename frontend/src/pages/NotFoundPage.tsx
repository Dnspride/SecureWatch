import React from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { Button } from "../components/ui/Button";

export const NotFoundPage: React.FC = () => {
  return (
    <div className="flex h-96 flex-col items-center justify-center text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-white border border-slate-200 text-[#0078d4] dark:bg-[#131b2e] dark:border-slate-800 dark:text-blue-400">
        <ShieldAlert className="h-8 w-8" />
      </div>
      <h1 className="mt-4 text-3xl font-bold text-slate-900 dark:text-white">404 - Page Not Found</h1>
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
        The requested cybersecurity console resource does not exist or has been relocated.
      </p>
      <Link to="/dashboard" className="mt-6">
        <Button>Return to SOC Overview</Button>
      </Link>
    </div>
  );
};
