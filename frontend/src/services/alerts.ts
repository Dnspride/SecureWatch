import api from './api';
import {
  Alert,
  AlertUpdateRequest,
  AlertNoteCreateRequest,
  AlertNote,
  AlertSeverity,
  AlertStatus,
  PaginatedResponse,
  PaginationParams,
} from '../types';

export interface AlertListParams extends PaginationParams {
  severity?: AlertSeverity;
  status?: AlertStatus;
  device_id?: string;
  start_date?: string;
  end_date?: string;
  assigned_to?: string;
}

export const alertsService = {
  list: (params?: AlertListParams) =>
    api.get<PaginatedResponse<Alert>>('/alerts', { params }).then((r) => r.data),

  get: (id: string) => api.get<Alert>(`/alerts/${id}`).then((r) => r.data),

  update: (id: string, data: AlertUpdateRequest) =>
    api.patch<Alert>(`/alerts/${id}`, data).then((r) => r.data),

  acknowledge: (id: string) =>
    api.post<Alert>(`/alerts/${id}/acknowledge`).then((r) => r.data),

  resolve: (id: string, resolution_notes?: string) =>
    api
      .post<Alert>(`/alerts/${id}/resolve`, { status: AlertStatus.RESOLVED, resolution_notes })
      .then((r) => r.data),

  markFalsePositive: (id: string, notes?: string) =>
    api
      .post<Alert>(`/alerts/${id}/resolve`, { status: AlertStatus.FALSE_POSITIVE, resolution_notes: notes })
      .then((r) => r.data),

  updateAlertStatus: (id: string, payload: { status: AlertStatus; resolution_notes?: string }) => {
    if (payload.status === AlertStatus.ACKNOWLEDGED) {
      return alertsService.acknowledge(id);
    }
    return api.post<Alert>(`/alerts/${id}/resolve`, payload).then((r) => r.data);
  },

  assign: (id: string, user_id: string) =>
    api.post<Alert>(`/alerts/${id}/assign`, { user_id }).then((r) => r.data),

  addNote: (id: string, data: AlertNoteCreateRequest | { content: string }) =>
    api.post<AlertNote>(`/alerts/${id}/notes`, data).then((r) => r.data),

  getNotes: (id: string) =>
    api.get<AlertNote[]>(`/alerts/${id}/notes`).then((r) => r.data),

  // Aliases for page compatibility
  getAlerts: (params?: AlertListParams) => alertsService.list(params),
  getAlert: (id: string) => alertsService.get(id),
  acknowledgeAlert: (id: string) => alertsService.acknowledge(id),
};

export const alertService = alertsService;
export default alertsService;
