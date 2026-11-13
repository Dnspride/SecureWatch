import { io, Socket } from 'socket.io-client';
import { Alert, Device, SecurityEvent, DashboardStats } from '../types';

const getWsUrl = () => {
  if (typeof window !== 'undefined') {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.hostname}:8000`;
  }
  return 'ws://localhost:8000';
};

const WS_URL = getWsUrl();

class WebSocketService {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectDelay = 1000;

  connect(token: string): void {
    if (this.socket?.connected) return;

    this.socket = io(WS_URL, {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: this.maxReconnectAttempts,
      reconnectionDelay: this.reconnectDelay,
      reconnectionDelayMax: 10000,
      timeout: 20000,
    });

    this.socket.on('connect', () => {
      console.log('[WS] Connected:', this.socket?.id);
      this.reconnectAttempts = 0;
    });

    this.socket.on('disconnect', (reason) => {
      console.warn('[WS] Disconnected:', reason);
    });

    this.socket.on('connect_error', (err) => {
      console.error('[WS] Connection error:', err.message);
      this.reconnectAttempts++;
    });
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  get isConnected(): boolean {
    return this.socket?.connected ?? false;
  }

  get socketId(): string | undefined {
    return this.socket?.id;
  }

  // ─── Event listeners ─────────────────────────────────────

  onDashboardUpdate(callback: (stats: DashboardStats) => void): () => void {
    this.socket?.on('dashboard_update', callback);
    return () => this.socket?.off('dashboard_update', callback);
  }

  onNewAlert(callback: (alert: Alert) => void): () => void {
    this.socket?.on('new_alert', callback);
    return () => this.socket?.off('new_alert', callback);
  }

  onAlertUpdated(callback: (alert: Alert) => void): () => void {
    this.socket?.on('alert_updated', callback);
    return () => this.socket?.off('alert_updated', callback);
  }

  onDeviceStatusChange(callback: (device: Device) => void): () => void {
    this.socket?.on('device_status_change', callback);
    return () => this.socket?.off('device_status_change', callback);
  }

  onLiveEvent(callback: (event: SecurityEvent) => void): () => void {
    this.socket?.on('security_event', callback);
    return () => this.socket?.off('security_event', callback);
  }

  onConnectionStatus(callback: (status: boolean) => void): () => void {
    const onConnect = () => callback(true);
    const onDisconnect = () => callback(false);
    this.socket?.on('connect', onConnect);
    this.socket?.on('disconnect', onDisconnect);
    return () => {
      this.socket?.off('connect', onConnect);
      this.socket?.off('disconnect', onDisconnect);
    };
  }

  emit(event: string, data?: unknown): void {
    this.socket?.emit(event, data);
  }
}

export const wsService = new WebSocketService();
export default wsService;
