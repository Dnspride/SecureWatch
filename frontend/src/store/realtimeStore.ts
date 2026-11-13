import { create } from 'zustand';
import { Alert, Device, SecurityEvent, DashboardStats, RealtimeEvent } from '../types';

const MAX_QUEUE = 50;

interface RealtimeState {
  isConnected: boolean;
  dashboardStats: DashboardStats | null;
  liveAlerts: Alert[];
  connectedDevices: Map<string, Device>;
  eventFeed: SecurityEvent[];
  realtimeEvents: RealtimeEvent[];
  // Actions
  setConnected: (connected: boolean) => void;
  setDashboardStats: (stats: DashboardStats) => void;
  pushAlert: (alert: Alert) => void;
  updateDevice: (device: Device) => void;
  pushEvent: (event: SecurityEvent) => void;
  pushRealtimeEvent: (event: RealtimeEvent) => void;
  clearFeed: () => void;
}

export const useRealtimeStore = create<RealtimeState>((set) => ({
  isConnected: false,
  dashboardStats: null,
  liveAlerts: [],
  connectedDevices: new Map(),
  eventFeed: [],
  realtimeEvents: [],

  setConnected: (connected) => set({ isConnected: connected }),

  setDashboardStats: (stats) => set({ dashboardStats: stats }),

  pushAlert: (alert) =>
    set((s) => ({
      liveAlerts: [alert, ...s.liveAlerts].slice(0, MAX_QUEUE),
    })),

  updateDevice: (device) =>
    set((s) => {
      const next = new Map(s.connectedDevices);
      next.set(device.id, device);
      return { connectedDevices: next };
    }),

  pushEvent: (event) =>
    set((s) => ({
      eventFeed: [event, ...s.eventFeed].slice(0, MAX_QUEUE),
    })),

  pushRealtimeEvent: (event) =>
    set((s) => ({
      realtimeEvents: [event, ...s.realtimeEvents].slice(0, MAX_QUEUE),
    })),

  clearFeed: () => set({ eventFeed: [], realtimeEvents: [], liveAlerts: [] }),
}));
