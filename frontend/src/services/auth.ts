import api from './api';
import { LoginRequest, LoginResponse, TokenPair, User } from '../types';

export const authService = {
  login: (data: LoginRequest) =>
    api.post<LoginResponse>('/auth/login', data).then((r) => r.data),

  logout: () => api.post('/auth/logout').then((r) => r.data),

  refresh: (refreshToken: string) =>
    api
      .post<TokenPair>('/auth/token/refresh', { refresh_token: refreshToken })
      .then((r) => r.data),

  me: () => api.get<User>('/auth/me').then((r) => r.data),
  getMe: () => api.get<User>('/auth/me').then((r) => r.data),

  setupMfa: () =>
    api.post<{ qr_code: string; secret: string }>('/auth/mfa/setup').then((r) => r.data),

  verifyMfa: (code: string) =>
    api.post<{ success: boolean }>('/auth/mfa/verify', { code }).then((r) => r.data),

  disableMfa: (code: string) =>
    api.post<{ success: boolean }>('/auth/mfa/disable', { code }).then((r) => r.data),

  changePassword: (data: { current_password: string; new_password: string }) =>
    api.post<{ success: boolean }>('/auth/change-password', data).then((r) => r.data),
};
