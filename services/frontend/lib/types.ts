export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Target {
  id: number;
  domain: string;
}

export interface Finding {
  id: number;
  type: string;
  severity: Severity;
  evidence: string;
  line: number;
  url: string; 
}

export interface Metrics {
  critical: number;
  intel: number;
  shadow: number;
}

export interface DashboardData {
  targets: Target[];
  findings: Finding[];
  metrics: Metrics;
}