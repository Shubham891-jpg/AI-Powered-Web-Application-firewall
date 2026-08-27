import axios from 'axios';
import { HealthData, PublicConfig } from '../types/health';

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
};
