import api from './api';
import { Device, DeviceStatus, EnrollmentToken, EnrollmentTokenResponse, PaginatedResponse, PaginationParams } from '../types';

export interface DeviceListParams extends PaginationParams {
  status?: DeviceStatus | string;
  os?: string;
  department?: string;
  search?: string;
}

export const devicesService = {
  list: (params?: DeviceListParams) =>
    api.get<PaginatedResponse<Device>>('/devices', { params }).then((r) => r.data),

  get: (id: string) => api.get<Device>(`/devices/${id}`).then((r) => r.data),

  generateEnrollmentToken: (data?: any) =>
    api.post<EnrollmentTokenResponse>('/devices/enrollment-token', data || { hours_valid: 24, requires_approval: false }).then((r) => r.data),

  createEnrollmentToken: (data?: any) =>
    api.post<EnrollmentTokenResponse>('/devices/enrollment-token', data || { hours_valid: 24, requires_approval: false }).then((r) => r.data),

  approve: (id: string) =>
    api.post<Device>(`/devices/${id}/approve`).then((r) => r.data),

  revoke: (id: string, reason?: string) =>
    api.post<Device>(`/devices/${id}/revoke`, { reason: reason || 'Administrative quarantine' }).then((r) => r.data),

  rotateCredentials: (id: string, reason?: string) =>
    api.post<Device>(`/devices/${id}/rotate-credentials`, { reason: reason || 'Key rotation' }).then((r) => r.data),

  delete: (id: string) => api.delete(`/devices/${id}`).then((r) => r.data),

  tags: {
    add: (id: string, tags: string[]) =>
      api.post<Device>(`/devices/${id}/tags`, { tags }).then((r) => r.data),
    remove: (id: string, tags: string[]) =>
      api.delete<Device>(`/devices/${id}/tags`, { data: { tags } }).then((r) => r.data),
  },

  // Aliases for page compatibility
  getDevices: (params?: DeviceListParams) => devicesService.list(params),
  getDevice: (id: string) => devicesService.get(id),
  approveDevice: (id: string) => devicesService.approve(id),
  revokeDevice: (id: string, reason?: string) => devicesService.revoke(id, reason),
};

export const deviceService = devicesService;
export default devicesService;
