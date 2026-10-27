export type ChannelType = 'EMAIL' | 'SMS' | 'WEB' | 'QR' | 'TELEPHONY_VISHING';
export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'NEW' | 'TRIAGED' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED_MALICIOUS' | 'CLOSED_FALSE_POSITIVE';
export type VerdictType = 'BENIGN' | 'SUSPICIOUS' | 'MALICIOUS';

export interface DomainFeatures {
  domain: string;
  entropy: number;
  length: number;
  has_ip_address: boolean;
  suspicious_tld: boolean;
  typosquatting_detected: boolean;
  homograph_detected: boolean;
  matched_target_brand?: string;
  similarity_ratio: number;
  domain_age_days?: number;
  dns_resolves: boolean;
  nameservers: string[];
  has_valid_tls: boolean;
}

export interface URLAnalysisResult {
  url: string;
  verdict: VerdictType;
  risk_score: number;
  confidence: number;
  domain_features: DomainFeatures;
  llm_rationale?: string;
  recommended_mitigation: string[];
  incident_id?: string;
  scan_timestamp: string;
}

export interface ChannelDistribution {
  channel: ChannelType;
  count: number;
  percentage: number;
}

export interface TemporalTrendPoint {
  date: string;
  detections: number;
  malicious: number;
  benign: number;
}

export interface TopAttackerEntity {
  identifier: string;
  count: number;
  reputation_score: number;
  first_seen: string;
}

export interface DashboardKPIs {
  total_detections_last_30d: number;
  active_incidents: number;
  mean_time_to_detect_seconds: number;
  mean_time_to_respond_seconds: number;
  false_positive_rate: number;
  false_negative_estimate: number;
  channel_distribution: ChannelDistribution[];
  temporal_trends: TemporalTrendPoint[];
  top_attacking_domains: TopAttackerEntity[];
  top_attacking_ips: TopAttackerEntity[];
}

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'assistant';
  content: string;
  suggested_actions?: string[];
  timestamp: string;
}

