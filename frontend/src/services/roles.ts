import api from './api';
import { Role, RoleCreateRequest, Permission, PaginatedResponse, PaginationParams } from '../types';

export const rolesService = {
  list: (params?: PaginationParams) =>
    api.get<any>('/roles', { params }).then((r) => r.data),

  get: (id: string) => api.get<Role>(`/roles/${id}`).then((r) => r.data),

  create: (data: RoleCreateRequest | any) =>
    api.post<Role>('/roles', data).then((r) => r.data),

  update: (id: string, data: Partial<RoleCreateRequest>) =>
    api.put<Role>(`/roles/${id}`, data).then((r) => r.data),

  delete: (id: string) => api.delete(`/roles/${id}`).then((r) => r.data),

  addPermissions: (id: string, permission_ids: string[]) =>
    api.post<Role>(`/roles/${id}/permissions`, { permission_ids }).then((r) => r.data),

  removePermissions: (id: string, permission_ids: string[]) =>
    api.delete<Role>(`/roles/${id}/permissions`, { data: { permission_ids } }).then((r) => r.data),

  // Aliases for page compatibility
  getRoles: () => api.get<Role[]>('/roles').then((r) => r.data),
  getPermissions: () => api.get<Permission[]>('/permissions').then((r) => r.data),
  createRole: (data: any) => api.post<Role>('/roles', data).then((r) => r.data),
};

export const permissionsService = {
  list: (params?: PaginationParams) =>
    api.get<any>('/permissions', { params }).then((r) => r.data),

  getPermissions: () =>
    api.get<Permission[]>('/permissions').then((r) => r.data),

  listByCategory: () =>
    api.get<any>('/permissions/grouped').then((r) => r.data),
};

export const roleService = rolesService;
export const permissionService = permissionsService;
export default rolesService;
