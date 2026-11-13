import api from './api';
import { SecurityEvent, PaginatedResponse, PaginationParams, AlertSeverity, EventCategory } from '../types';

export interface EventSearchParams extends PaginationParams {
  device_id?: string;
  category?: EventCategory | string;
  event_category?: string;
  severity?: AlertSeverity | string;
  start_date?: string;
  end_date?: string;
  source_ip?: string;
  username?: string;
  event_type?: string;
  query?: string;
}

export const eventsService = {
  list: (params?: EventSearchParams) =>
    api.get<PaginatedResponse<SecurityEvent>>('/events', { params }).then((r) => r.data),

  get: (id: string) =>
    api.get<SecurityEvent>(`/events/${id}`).then((r) => r.data),

  searchEvents: (params?: EventSearchParams) =>
    api.post<PaginatedResponse<SecurityEvent>>('/events/search', {
      page: params?.page || 1,
      page_size: params?.page_size || 50,
      query: params?.query,
      device_id: params?.device_id,
      event_category: params?.event_category || params?.category,
      severity: params?.severity,
    }).then((r) => r.data),

  deviceEvents: (deviceId: string, params?: EventSearchParams) =>
    api
      .get<PaginatedResponse<SecurityEvent>>(`/devices/${deviceId}/events`, { params })
      .then((r) => r.data),

  export: (params?: EventSearchParams) =>
    api
      .get('/events/export', { params, responseType: 'blob' })
      .then((r) => r.data as Blob),
};

export const eventService = eventsService;
export default eventsService;
