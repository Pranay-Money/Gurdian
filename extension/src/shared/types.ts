export type ChannelType = 'email' | 'sms' | 'social' | 'url';
export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';
export type ActionType = 'allow' | 'warn' | 'block';
export type SignalCategory = 'linguistic' | 'structural' | 'reputation' | 'behavioral' | 'metadata';
export type VerdictType = 'false_positive' | 'false_negative' | 'correct';
export type IntelSource = 'google_safe_browsing' | 'virustotal' | 'abuseipdb' | 'urlhaus' | 'phishtank';
export type IntelVerdict = 'clean' | 'malicious' | 'suspicious' | 'unknown';

export interface EvidenceItem {
  type: string;
  value: string;
  description: string;
}

export interface Signal {
  key: string;
  category: SignalCategory;
  label: string;
  points: number;
  reason: string;
  evidence: EvidenceItem[];
}

export interface URLAnalysis {
  url: string;
  host: string;
  registrable_domain: string;
  tld: string;
  https: boolean;
  subdomains: string[];
  length: number;
  age_days?: number;
  redirects: string[];
  intel?: Record<IntelSource, { verdict: IntelVerdict; details: Record<string, unknown>; checked_at: string }>;
}

export interface AnalyzeRequest {
  channel: ChannelType;
  sender?: string;
  text?: string;
  urls: string[];
  options?: { deep?: boolean };
}

export interface AnalyzeResponse {
  case_id: string;
  score: number;
  level: RiskLevel;
  action: ActionType;
  signals: Signal[];
  urls: URLAnalysis[];
  model_version: string;
  latency_ms: number;
}

export interface CaseSummary {
  case_id: string;
  score: number;
  level: RiskLevel;
  action: ActionType;
  channel: ChannelType;
  created_at: string;
  sender?: string;
  url_count: number;
}

export interface CaseListResponse {
  cases: CaseSummary[];
  next_cursor?: string;
}

export interface CaseDetail extends AnalyzeResponse {
  sender?: string;
  text?: string;
  created_at: string;
  updated_at: string;
}

export interface FeedbackRequest {
  case_id: string;
  verdict: VerdictType;
  notes?: string;
}

export interface ReportRequest {
  url: string;
  note?: string;
}

export interface StatsResponse {
  total_cases: number;
  by_level: Record<RiskLevel, number>;
  by_channel: Record<ChannelType, number>;
  avg_score: number;
  avg_latency_ms: number;
}

export interface BlocklistEntry {
  domain_hash: string;
  reason: string;
  expires_at: string;
}

export interface BlocklistDeltaResponse {
  additions: BlocklistEntry[];
  removals: string[];
  timestamp: string;
}

export interface DeviceRegisterResponse {
  device_token: string;
  expires_at: string;
}

export interface ErrorResponse {
  error: { code: string; message: string; details?: Record<string, unknown> };
}

export type EnforcementPolicy = 'warn' | 'block';

export interface DeviceSettings {
  protectionEnabled: boolean;
  enforcementPolicy: EnforcementPolicy;
  showInlineBadges: boolean;
  sendTelemetry: boolean;
  apiBaseUrl: string;
  deviceToken: string;
  blocklistVersion: number;
  blocklistUpdatedAt: string;
  privacyMode: 'standard' | 'strict';
  customAllowlist: string[];
  customBlocklist: string[];
}

export const DEFAULT_SETTINGS: DeviceSettings = {
  protectionEnabled: true,
  enforcementPolicy: 'warn',
  showInlineBadges: true,
  sendTelemetry: false,
  apiBaseUrl: 'http://localhost:8000/v1',
  deviceToken: '',
  blocklistVersion: 0,
  blocklistUpdatedAt: '',
  privacyMode: 'standard',
  customAllowlist: [],
  customBlocklist: [],
};

export interface BlockData {
  url: string;
  reason: 'malicious' | 'inappropriate';
  timestamp: number;
  caseId?: string;
  score?: number;
  level?: RiskLevel;
  signals?: Signal[];
  autoBlocked?: boolean;
  blockSource?: 'blocklist' | 'ml' | 'heuristic';
}

// ===== Content Script Types =====

export interface LinkData {
  href: string;
  visibleText: string;
  element: HTMLAnchorElement;
  host: string;
  registrableDomain: string;
  isExternal: boolean;
  mismatchSignal?: Signal;
}

export interface DomainAnalysis {
  domain: string;
  level: RiskLevel;
  score: number;
  signals: Signal[];
  cached: boolean;
  analyzedAt: number;
}

export interface BadgeData {
  level: RiskLevel;
  score: number;
  topSignal?: Signal;
}

export type SupportedSite = 
  | 'gmail' 
  | 'outlook' 
  | 'whatsapp' 
  | 'telegram' 
  | 'linkedin' 
  | 'x' 
  | 'instagram';

export interface SiteConfig {
  key: SupportedSite;
  name: string;
  hostPatterns: string[];
  dmSelectors?: string[];  // Selectors to identify DM/conversation areas
  linkSelectors?: string[]; // Additional link selectors beyond 'a[href]'
}

export const SUPPORTED_SITES: Record<SupportedSite, SiteConfig> = {
  gmail: {
    key: 'gmail',
    name: 'Gmail',
    hostPatterns: ['*://mail.google.com/*'],
    dmSelectors: ['[role="main"]', '.a3s', '.ii.gt'],
    linkSelectors: ['a[href]'],
  },
  outlook: {
    key: 'outlook',
    name: 'Outlook Web',
    hostPatterns: ['*://outlook.live.com/*', '*://*.office.com/*', '*://*.office365.com/*'],
    dmSelectors: ['[role="main"]', '.rpsContent', '.readMsgBody'],
    linkSelectors: ['a[href]'],
  },
  whatsapp: {
    key: 'whatsapp',
    name: 'WhatsApp Web',
    hostPatterns: ['*://web.whatsapp.com/*'],
    dmSelectors: ['[data-testid="conversation-panel"]', '#main', '.copyable-area'],
    linkSelectors: ['a[href]'],
  },
  telegram: {
    key: 'telegram',
    name: 'Telegram Web',
    hostPatterns: ['*://web.telegram.org/*', '*://*.web.telegram.org/*'],
    dmSelectors: ['.chat-content', '.message', '.bubbles-inner'],
    linkSelectors: ['a[href]'],
  },
  linkedin: {
    key: 'linkedin',
    name: 'LinkedIn',
    hostPatterns: ['*://*.linkedin.com/*'],
    dmSelectors: ['.msg-thread', '.conversation-container', '[data-test-conversation]'],
    linkSelectors: ['a[href]'],
  },
  x: {
    key: 'x',
    name: 'X (Twitter)',
    hostPatterns: ['*://*.x.com/*', '*://twitter.com/*'],
    dmSelectors: ['[data-testid="dmConversation"]', '.dm-conversation', '[aria-label*="Message"]'],
    linkSelectors: ['a[href]'],
  },
  instagram: {
    key: 'instagram',
    name: 'Instagram',
    hostPatterns: ['*://*.instagram.com/*'],
    dmSelectors: ['[aria-label*="Direct"]', '.x78zum5', '[role="dialog"]'],
    linkSelectors: ['a[href]'],
  },
};

// ===== Context Menu / Analyze Popup Types =====

export interface AnalyzeTextRequest {
  text: string;
  channel: ChannelType;
  sender?: string;
  urls?: string[];
}

export interface AnalyzeTextResponse extends AnalyzeResponse {
  extractedUrls: ExtractedUrl[];
}

export interface ExtractedUrl {
  url: string;
  host: string;
  riskLevel: RiskLevel;
  signals: Signal[];
}

// ===== Extended Settings =====

export interface ExtendedDeviceSettings extends DeviceSettings {
  linkScanningEnabled: boolean;
  enabledSites: Record<SupportedSite, boolean>;
  badgeStyle: 'minimal' | 'detailed';
  warningDialogEnabled: boolean;
  maxLinksPerPage: number;
  batchSize: number;
  observerThrottleMs: number;
}

export const DEFAULT_EXTENDED_SETTINGS: ExtendedDeviceSettings = {
  ...DEFAULT_SETTINGS,
  linkScanningEnabled: false,
  enabledSites: {
    gmail: false,
    outlook: false,
    whatsapp: false,
    telegram: false,
    linkedin: false,
    x: false,
    instagram: false,
  },
  badgeStyle: 'minimal',
  warningDialogEnabled: true,
  maxLinksPerPage: 200,
  batchSize: 20,
  observerThrottleMs: 100,
};