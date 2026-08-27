export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'disabled';
  latency_ms: number | null;
  details: Record<string, any>;
}

export interface HealthData {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  environment: string;
  uptime_seconds: number;
  components: {
    upstream: ComponentHealth;
    redis: ComponentHealth;
    database: ComponentHealth;
    detection: ComponentHealth;
  };
}

export interface PublicConfig {
  app_name: string;
  version: string;
  environment: string;
  upstream_url: string;
  detection_mode: string;
  thresholds: {
    allow: number;
    flag: number;
    block: number;
  };
  rate_limiting: {
    requests: number;
    window_seconds: number;
  };
  limits: {
    max_body_bytes: number;
    max_header_bytes: number;
  };
}
