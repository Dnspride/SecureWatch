import api from './api';
import { AuditLog, PaginatedResponse, PaginationParams } from '../types';

export interface AuditListParams extends PaginationParams {
  actor_id?: string;
  actor_username?: string;
  action?: string;
  resource_type?: string;
  start_date?: string;
  end_date?: string;
  result?: 'success' | 'failure';
}

export const auditService = {
  list: (params?: AuditListParams) =>
    api.get<PaginatedResponse<AuditLog>>('/audit-logs', { params }).then((r) => r.data),

  get: (id: string) =>
    api.get<AuditLog>(`/audit-logs/${id}`).then((r) => r.data),

  export: (params?: AuditListParams) =>
    api
      .get('/audit-logs/export', { params, responseType: 'blob' })
      .then((r) => r.data as Blob),

  // Aliases for page compatibility
  getAuditLogs: (params?: AuditListParams) =>
    api.get<PaginatedResponse<AuditLog>>('/audit-logs', { params }).then((r) => r.data),

  verifyIntegrity: (limit: number = 1000) =>
    api.post<{ success: boolean; message: string }>('/audit-logs/verify-integrity', { limit }).then((r) => r.data),
};

export default auditService;
