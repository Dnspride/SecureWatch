import api from './api';
import { DashboardStats } from '../types';

export const dashboardService = {
  getStats: () =>
    api.get<DashboardStats>('/dashboard/stats').then((r) => r.data),
};
