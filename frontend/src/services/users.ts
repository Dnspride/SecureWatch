import api from './api';
import { User, UserCreateRequest, UserUpdateRequest, PaginatedResponse, PaginationParams, LoginHistory } from '../types';

export interface UserListParams extends PaginationParams {
  status?: string;
  role?: string;
  department?: string;
  search?: string;
}

export const usersService = {
  list: (params?: UserListParams) =>
    api.get<PaginatedResponse<User>>('/users', { params }).then((r) => r.data),

  get: (id: string) => api.get<User>(`/users/${id}`).then((r) => r.data),

  create: (data: UserCreateRequest | any) =>
    api.post<User>('/users', data).then((r) => r.data),

  update: (id: string, data: UserUpdateRequest | any) =>
    api.put<User>(`/users/${id}`, data).then((r) => r.data),

  delete: (id: string) => api.delete(`/users/${id}`).then((r) => r.data),

  lock: (id: string) => api.post<User>(`/users/${id}/lock`).then((r) => r.data),

  unlock: (id: string) => api.post<User>(`/users/${id}/unlock`).then((r) => r.data),

  resetPassword: (id: string, new_password: string) =>
    api.post(`/users/${id}/reset-password`, { new_password }).then((r) => r.data),

  loginHistory: (id: string, params?: PaginationParams) =>
    api
      .get<PaginatedResponse<LoginHistory>>(`/users/${id}/login-history`, { params })
      .then((r) => r.data),

  activeSessions: (id: string) =>
    api.get<{ sessions: Array<{ id: string; ip: string; created_at: string; last_active: string }> }>(`/users/${id}/sessions`).then((r) => r.data),

  revokeSession: (userId: string, sessionId: string) =>
    api.delete(`/users/${userId}/sessions/${sessionId}`).then((r) => r.data),

  // Aliases for page compatibility
  getUsers: (params?: UserListParams) => usersService.list(params),
  createUser: (data: any) => usersService.create(data),
  lockUser: (id: string) => usersService.lock(id),
  unlockUser: (id: string) => usersService.unlock(id),
  deleteUser: (id: string) => usersService.delete(id),
};

export const userService = usersService;
export default usersService;
