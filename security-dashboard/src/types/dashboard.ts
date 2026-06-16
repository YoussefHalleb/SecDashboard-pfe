export type RecommendationStatus = "proposed" | "approved" | "rejected";

export interface Recommendation {
  id: string;
  finding_id: number;
  content: string;
  status: RecommendationStatus;
  title?: string;
  cvss_score?: number;
  cvss_vector?: string;
  ai_risk_score?: number;
  confidence?: number;
  false_positive_likelihood?: string;
  priority?: string;
  attack_complexity?: string;
  privileges_required?: string;
  user_interaction?: string;
  owasp_category?: string;
  code_fix_example?: string;
  jira_issue_key?: string;
  jira_issue_url?: string;
  jira_pending?: boolean;
}

export interface Vulnerability {
  id: number;
  title: string;
  severity: string;
  component_name: string;
  scanner: string;
  description?: string;
}

export interface Repository {
  id: number;
  name: string;
  vulnerabilities: Vulnerability[];
}
