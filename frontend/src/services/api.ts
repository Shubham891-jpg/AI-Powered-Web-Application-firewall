import axios from 'axios';
import { HealthData, PublicConfig } from '../types/health';
import { SecurityEventItem, DashboardSummary, ApplicationItem, RuleItem } from '../types/security';

const API_BASE = '';

export const api = {
  getHealth: async (): Promise<HealthData> => {
    const response = await axios.get<HealthData>(`${API_BASE}/api/health`);
    return response.data;
  },

  getConfig: async (): Promise<PublicConfig> => {
    const response = await axios.get<PublicConfig>(`${API_BASE}/api/v1/config`);
    return response.data;
  },

  probeHealthLiveness: async (): Promise<boolean> => {
    try {
      const response = await axios.get(`${API_BASE}/health`);
      return response.status === 200;
    } catch {
      return false;
    }
  },

  getSecurityEvents: async (params?: {
    category?: string;
    action?: string;
    min_risk?: number;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ total: number; limit: number; offset: number; events: SecurityEventItem[] }> => {
    const response = await axios.get(`${API_BASE}/api/v1/security-events`, { params });
    return response.data;
  },

  getSummary: async (): Promise<DashboardSummary> => {
    const response = await axios.get<DashboardSummary>(`${API_BASE}/api/v1/security-events/summary`);
    return response.data;
  },

  getEventDetail: async (id: string): Promise<SecurityEventItem> => {
    const response = await axios.get<SecurityEventItem>(`${API_BASE}/api/v1/security-events/${id}`);
    return response.data;
  },

  getApplications: async (): Promise<ApplicationItem[]> => {
    const response = await axios.get<ApplicationItem[]>(`${API_BASE}/api/v1/applications`);
    return response.data;
  },

  createApplication: async (payload: Partial<ApplicationItem>): Promise<ApplicationItem> => {
    const response = await axios.post<ApplicationItem>(`${API_BASE}/api/v1/applications`, payload);
    return response.data;
  },

  updateApplication: async (id: string, payload: Partial<ApplicationItem>): Promise<ApplicationItem> => {
    const response = await axios.patch<ApplicationItem>(`${API_BASE}/api/v1/applications/${id}`, payload);
    return response.data;
  },

  getRules: async (): Promise<RuleItem[]> => {
    const response = await axios.get<RuleItem[]>(`${API_BASE}/api/v1/rules`);
    return response.data;
  },

  updateRule: async (ruleId: string, payload: { enabled?: boolean; score?: number }): Promise<RuleItem> => {
    const response = await axios.patch<RuleItem>(`${API_BASE}/api/v1/rules/${ruleId}`, payload);
    return response.data;
  },
};
