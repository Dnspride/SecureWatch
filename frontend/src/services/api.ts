import axios, { AxiosError, AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import { ApiError } from '../types';

const BASE_URL = typeof window !== 'undefined' ? '' : 'http://localhost:8000';

export const api = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

// ─── Token refresh state ─────────────────────────────────────
let isRefreshing = false;
let refreshSubscribers: Array<(token: string) => void> = [];

function subscribeTokenRefresh(cb: (token: string) => void) {
  refreshSubscribers.push(cb);
}

function onRefreshed(token: string) {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

// ─── Request interceptor: attach access token ────────────────
api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  try {
    let token: string | undefined = localStorage.getItem('access_token') || undefined;
    if (!token) {
      const raw = localStorage.getItem('auth-storage');
      if (raw) {
        const parsed = JSON.parse(raw);
        token = parsed?.state?.accessToken;
      }
    }
    if (token && config.headers) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
  } catch {
    // ignore JSON parse errors
  }
  return config;
});

// ─── Response interceptor: 401 → refresh → retry ────────────
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise<string>((resolve) => {
          subscribeTokenRefresh(resolve);
        }).then((token) => {
          if (originalRequest.headers) {
            (originalRequest.headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
          }
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const raw = localStorage.getItem('auth-storage');
        const parsed = raw ? JSON.parse(raw) : null;
        const refreshToken: string | undefined = parsed?.state?.refreshToken;

        if (!refreshToken) throw new Error('No refresh token');

        const { data } = await axios.post(`${BASE_URL}/api/v1/auth/token/refresh`, {
          refresh_token: refreshToken,
        });

        const newAccessToken: string = data.access_token;

        // Patch localStorage directly (Zustand store will sync on next render)
        if (parsed?.state) {
          parsed.state.accessToken = newAccessToken;
          localStorage.setItem('auth-storage', JSON.stringify(parsed));
        }

        onRefreshed(newAccessToken);
        isRefreshing = false;

        if (originalRequest.headers) {
          (originalRequest.headers as Record<string, string>)['Authorization'] = `Bearer ${newAccessToken}`;
        }
        return api(originalRequest);
      } catch (refreshError) {
        isRefreshing = false;
        refreshSubscribers = [];
        // Clear auth and redirect to login
        localStorage.removeItem('auth-storage');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }

    // Build typed ApiError
    const apiError: ApiError = {
      message:
        (error.response?.data as Record<string, string>)?.detail ||
        (error.response?.data as Record<string, string>)?.message ||
        error.message ||
        'An unexpected error occurred',
      detail: (error.response?.data as Record<string, unknown>)?.detail as string | Record<string, unknown>,
      status_code: error.response?.status,
    };

    return Promise.reject(apiError);
  }
);

export default api;
