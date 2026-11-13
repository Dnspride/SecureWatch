import api from './api';
import { Report, ReportType, PaginatedResponse, PaginationParams } from '../types';

export const reportsService = {
  list: (params?: PaginationParams) =>
    api.get<PaginatedResponse<Report>>('/reports', { params }).then((r) => r.data),

  get: (id: string) => api.get<Report>(`/reports/${id}`).then((r) => r.data),

  generate: (report_type: ReportType, parameters?: Record<string, unknown>) =>
    api.post<Report>('/reports/generate', { report_type, parameters }).then((r) => r.data),

  download: (id: string) =>
    api.get(`/reports/${id}/download`, { responseType: 'blob' }).then((r) => r.data as Blob),

  delete: (id: string) => api.delete(`/reports/${id}`).then((r) => r.data),
};
