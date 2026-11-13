// ============================================================
// SecureWatch – Shared TypeScript Types
// ============================================================

// ─── Enumerations ───────────────────────────────────────────

export enum DeviceStatus {
  PENDING = 'pending',
  APPROVED = 'approved',
  REVOKED = 'revoked',
  OFFLINE = 'offline',
  ONLINE = 'online',
}

export enum AlertSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export enum AlertStatus {
  OPEN = 'open',
  ACKNOWLEDGED = 'acknowledged',
  INVESTIGATING = 'investigating',
  RESOLVED = 'resolved',
  FALSE_POSITIVE = 'false_positive',
}

export enum EventCategory {
  AUTHENTICATION = 'authentication',
  PROCESS = 'process',
  NETWORK = 'network',
  FILE = 'file',
  SYSTEM = 'system',
  DNS = 'dns',
  REGISTRY = 'registry',
}

export enum UserStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  LOCKED = 'locked',
  SUSPENDED = 'suspended',
}

// ─── Auth ────────────────────────────────────────────────────

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  mfa_code?: string;
}

export interface LoginResponse extends TokenPair {
  requires_mfa?: boolean;
  mfa_method?: string;
}

// ─── Permission ──────────────────────────────────────────────

export interface Permission {
  id: string;
  name: string;           // e.g. "users.read"
  display_name: string;
  description?: string;
  category: string;       // e.g. "users", "devices"
  created_at: string;
}

// ─── Role ────────────────────────────────────────────────────

export interface Role {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  is_system_role: boolean;
  permissions: Permission[];
  permission_count?: number;
  user_count?: number;
  created_at: string;
  updated_at: string;
}

export interface RoleCreateRequest {
  name: string;
  display_name: string;
  description?: string;
  permission_ids: string[];
}

// ─── Group ───────────────────────────────────────────────────

export interface Group {
  id: string;
  name: string;
  display_name: string;
  description?: string;
  department?: string;
  member_count?: number;
  role_count?: number;
  roles: Role[];
  members?: User[];
  created_at: string;
  updated_at: string;
}

export interface GroupCreateRequest {
  name: string;
  display_name: string;
  description?: string;
  department?: string;
  role_ids: string[];
}

// ─── User ────────────────────────────────────────────────────

export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string;
  department?: string;
  job_title?: string;
  phone?: string;
  status: UserStatus;
  is_mfa_enabled: boolean;
  mfa_method?: string;
  roles: Role[];
  groups: Group[];
  last_login?: string;
  failed_login_attempts: number;
  account_locked_until?: string;
  created_at: string;
  updated_at: string;
}

export interface UserCreateRequest {
  username: string;
  email: string;
  full_name: string;
  password: string;
  department?: string;
  job_title?: string;
  phone?: string;
  role_ids?: string[];
  group_ids?: string[];
}

export interface UserUpdateRequest {
  email?: string;
  full_name?: string;
  department?: string;
  job_title?: string;
  phone?: string;
  status?: UserStatus;
  role_ids?: string[];
  group_ids?: string[];
}

// ─── Device ──────────────────────────────────────────────────

export interface Device {
  id: string;
  hostname: string;
  device_type: string;
  os_name: string;
  os_version: string;
  os_arch: string;
  ip_address?: string;
  mac_address?: string;
  status: DeviceStatus;
  risk_score: number;
  agent_version?: string;
  owner?: User;
  department?: string;
  last_heartbeat?: string;
  enrolled_at?: string;
  approved_at?: string;
  approved_by?: string;
  revoked_at?: string;
  revoke_reason?: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface EnrollmentToken {
  id?: string;
  token: string;
  expires_at: string;
  created_at?: string;
  requires_approval?: boolean;
  is_used?: boolean;
  enrollment_command?: string;
}

export interface EnrollmentTokenResponse {
  id: string;
  token: string;
  created_at: string;
  expires_at: string;
  requires_approval: boolean;
  is_used: boolean;
  enrollment_command?: string;
}

// ─── Security Event ──────────────────────────────────────────

export interface SecurityEvent {
  id: string;
  event_id: string;
  device_id: string;
  device?: Device;
  category: EventCategory;
  event_type: string;
  severity: AlertSeverity;
  source_ip?: string;
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  username?: string;
  process_name?: string;
  process_id?: number;
  file_path?: string;
  raw_data: Record<string, unknown>;
  normalized_data: Record<string, unknown>;
  tags: string[];
  timestamp: string;
  ingested_at: string;
}

// ─── Alert ───────────────────────────────────────────────────

export interface AlertNote {
  id: string;
  alert_id: string;
  author: User;
  content: string;
  created_at: string;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: AlertStatus;
  device_id?: string;
  device?: Device;
  event_id?: string;
  triggering_event?: SecurityEvent;
  rule_id?: string;
  rule_name?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_technique_id?: string;
  recommended_steps?: string[];
  assigned_to?: User;
  acknowledged_at?: string;
  acknowledged_by?: string;
  resolved_at?: string;
  resolved_by?: string;
  resolution_notes?: string;
  notes: AlertNote[];
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface AlertUpdateRequest {
  status?: AlertStatus;
  assigned_to_id?: string;
  resolution_notes?: string;
}

export interface AlertNoteCreateRequest {
  content: string;
}

// ─── Audit Log ───────────────────────────────────────────────

export interface AuditLog {
  id: string;
  actor_id?: string;
  actor?: User;
  actor_username?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  resource_name?: string;
  details?: Record<string, unknown>;
  source_ip?: string;
  user_agent?: string;
  result: 'success' | 'failure';
  error_message?: string;
  timestamp: string;
}

// ─── Dashboard Stats ─────────────────────────────────────────

export interface DashboardStats {
  total_users: number;
  active_users: number;
  total_devices: number;
  online_devices: number;
  pending_devices: number;
  critical_alerts: number;
  open_alerts: number;
  security_events_today: number;
  failed_logins_today: number;
  events_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  alerts_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  events_over_time: Array<{
    date: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  }>;
  os_distribution: Array<{
    os: string;
    count: number;
  }>;
  failed_logins_trend: Array<{
    hour: string;
    count: number;
  }>;
  recent_alerts: Alert[];
  device_health: Device[];
}

// ─── Realtime Events ─────────────────────────────────────────

export type RealtimeEventType =
  | 'new_alert'
  | 'alert_updated'
  | 'device_status_change'
  | 'new_security_event'
  | 'dashboard_update'
  | 'user_login'
  | 'device_enrolled';

export interface RealtimeEvent {
  type: RealtimeEventType;
  payload: Alert | Device | SecurityEvent | DashboardStats | Record<string, unknown>;
  timestamp: string;
}

// ─── Pagination ──────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface PaginationParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  search?: string;
}

// ─── Detection Rules ─────────────────────────────────────────

export interface DetectionRule {
  id: string;
  name: string;
  description?: string;
  severity: AlertSeverity;
  category: EventCategory;
  is_enabled: boolean;
  mitre_tactic?: string;
  mitre_technique?: string;
  conditions: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

// ─── Reports ─────────────────────────────────────────────────

export type ReportType =
  | 'security_summary'
  | 'user_activity'
  | 'device_inventory'
  | 'alert_summary'
  | 'audit_log'
  | 'compliance';

export interface Report {
  id: string;
  name: string;
  report_type: ReportType;
  generated_by?: User;
  parameters?: Record<string, unknown>;
  file_url?: string;
  file_format: 'pdf' | 'csv' | 'json';
  status: 'pending' | 'generating' | 'completed' | 'failed';
  error?: string;
  created_at: string;
  completed_at?: string;
}

// ─── Settings ────────────────────────────────────────────────

export interface PlatformSettings {
  platform_name: string;
  logo_url?: string;
  max_failed_logins: number;
  lockout_duration_minutes: number;
  session_timeout_minutes: number;
  require_mfa: boolean;
  log_retention_days: number;
  alert_email_enabled: boolean;
  alert_email_recipients: string[];
  webhook_url?: string;
}

// ─── API Error ───────────────────────────────────────────────

export interface ApiError {
  message: string;
  detail?: string | Record<string, unknown>;
  status_code?: number;
}

// ─── Login History ───────────────────────────────────────────

export interface LoginHistory {
  id: string;
  user_id: string;
  ip_address: string;
  user_agent?: string;
  status: 'success' | 'failed';
  failure_reason?: string;
  timestamp: string;
}
