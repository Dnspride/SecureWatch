import React from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export const AppLayout: React.FC = () => {
  return (
    <div className="min-h-screen bg-[#f4f6f8] dark:bg-[#0b0f19] text-slate-800 dark:text-slate-100 flex transition-colors duration-200">
      <Sidebar />
      <div className="pl-64 flex flex-col flex-1 min-h-screen">
        <TopBar />
        <main className="flex-1 p-6 md:p-8 bg-[#f4f6f8] dark:bg-[#0b0f19] transition-colors duration-200">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
