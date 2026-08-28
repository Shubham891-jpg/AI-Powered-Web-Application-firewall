export interface SecurityEventItem {
  id: string;
  request_id: string;
  timestamp: string;
  client_ip: string;
  http_method: string;
  path: string;
  attack_category: string;
  risk_score: number;
  action: 'ALLOW' | 'FLAG' | 'BLOCK' | 'RATE_LIMITED';
  primary_reason: string;
  processing_latency_ms: number;
  matched_rules?: Array<{
    rule_id: string;
    name: string;
    category?: string;
    confidence: string;
    score: number;
  }>;
  ml_prediction?: {
    predicted_class: string;
    confidence: number;
    model_name?: string;
    model_version?: string;
    latency_ms?: number;
  };
  contextual_penalties?: Array<{
    factor: string;
    penalty_points: number;
    reason?: string;
  }>;
  raw_payload?: string;
  normalized_payload?: string;
}

export interface DashboardSummary {
  total_requests: number;
  allowed_requests: number;
  flagged_requests: number;
  blocked_requests: number;
  threat_rate_percentage: number;
  requests_per_second: number;
  avg_inspection_latency_ms: number;
  attack_distribution: Record<string, number>;
}

export interface ApplicationItem {
  id: string;
  name: string;
  upstream_url: string;
  is_active: boolean;
  detection_mode: string;
  rate_limit_requests: number;
  rate_limit_window_seconds?: number;
}

export interface RuleItem {
  rule_id: string;
  name: string;
  category: string;
  score: number;
  enabled: boolean;
}
