import api from './api';
import { Group, GroupCreateRequest, PaginatedResponse, PaginationParams } from '../types';

export const groupsService = {
  list: (params?: PaginationParams) =>
    api.get<any>('/groups', { params }).then((r) => r.data),

  get: (id: string) => api.get<Group>(`/groups/${id}`).then((r) => r.data),

  create: (data: GroupCreateRequest | any) =>
    api.post<Group>('/groups', data).then((r) => r.data),

  update: (id: string, data: Partial<GroupCreateRequest>) =>
    api.put<Group>(`/groups/${id}`, data).then((r) => r.data),

  delete: (id: string) => api.delete(`/groups/${id}`).then((r) => r.data),

  addMember: (groupId: string, userId: string) =>
    api.post(`/groups/${groupId}/members`, { user_id: userId }).then((r) => r.data),

  removeMember: (groupId: string, userId: string) =>
    api.delete(`/groups/${groupId}/members/${userId}`).then((r) => r.data),

  // Aliases for page compatibility
  getGroups: () => api.get<Group[]>('/groups').then((r) => r.data),
  createGroup: (data: any) => api.post<Group>('/groups', data).then((r) => r.data),
};

export const groupService = groupsService;
export default groupsService;
