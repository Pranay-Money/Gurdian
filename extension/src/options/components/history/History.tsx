import React, { useState, useMemo, useCallback, useEffect } from 'react';
import { Signal, RiskLevel, ActionType, ChannelType } from '@shared/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../common/Card';
import { Button } from '../common/Button';
import { Input } from '../common/Input';
import { Select } from '../common/Select';
import { Badge, RiskBadge, ActionBadge } from '../common/Badge';
import { VirtualizedTable, createHistoryColumns, SignalTable } from '../common/Table';
import { formatRelativeTime, truncateUrl, RISK_LEVEL_COLORS, CHANNEL_LABELS, SOURCE_LABELS } from '../../hooks/useSettings';
import { clsx } from 'clsx';
import { Search, Filter, X, ChevronDown, Download, Upload } from 'lucide-react';

interface HistoryEntry {
  id?: number;
  timestamp: number;
  url: string;
  host: string;
  registrableDomain: string;
  score: number;
  level: RiskLevel;
  action: ActionType;
  signals: Signal[];
  urlAnalysis?: URLAnalysis[];
  explanation: string;
  source: 'allowlist' | 'blocklist' | 'heuristics' | 'api' | 'fail-open';
  latencyMs: number;
  privacyMode: 'standard' | 'strict';
  channel: ChannelType;
  sender?: string;
  text?: string;
}

interface URLAnalysis {
  url: string;
  host: string;
  registrable_domain: string;
  tld: string;
  https: boolean;
  subdomains: string[];
  length: number;
  age_days?: number;
  redirects: string[];
}

interface HistoryFilters {
  query: string;
  level: RiskLevel | '';
  source: HistoryEntry['source'] | '';
  channel: ChannelType | '';
  domain: string;
  from: number | '';
  to: number | '';
}

interface HistoryProps {
  entries: HistoryEntry[];
  onLoadEntries: (filters: HistoryFilters) => void;
  loading: boolean;
  onRowClick?: (entry: HistoryEntry) => void;
}

const RISK_LEVELS: RiskLevel[] = ['Low', 'Medium', 'High', 'Critical'];
const SOURCES: HistoryEntry['source'][] = ['allowlist', 'blocklist', 'heuristics', 'api', 'fail-open'];
const CHANNELS: ChannelType[] = ['email', 'sms', 'social', 'url'];

export function History({ entries, onLoadEntries, loading, onRowClick }: HistoryProps) {
  const [filters, setFilters] = useState<HistoryFilters>({
    query: '',
    level: '',
    source: '',
    channel: '',
    domain: '',
    from: '',
    to: '',
  });
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [selectedEntry, setSelectedEntry] = useState<HistoryEntry | null>(null);
  const [exportFormat, setExportFormat] = useState<'json' | 'csv'>('json');

  const debouncedFilters = useMemo(() => filters, [filters]);

  useEffect(() => {
    const timeout = setTimeout(() => {
      onLoadEntries(debouncedFilters);
    }, 300);
    return () => clearTimeout(timeout);
  }, [debouncedFilters, onLoadEntries]);

  const handleFilterChange = useCallback((key: keyof HistoryFilters, value: HistoryFilters[keyof HistoryFilters]) => {
    setFilters(prev => ({ ...prev, [key]: value }));
  }, []);

  const clearFilters = useCallback(() => {
    setFilters({
      query: '',
      level: '',
      source: '',
      channel: '',
      domain: '',
      from: '',
      to: '',
    });
  }, []);

  const hasActiveFilters = useMemo(() => 
    Object.values(filters).some(v => v !== ''), [filters]);

  const uniqueDomains = useMemo(() => 
    [...new Set(entries.map(e => e.registrableDomain))].sort(), [entries]);

  const handleExport = useCallback(async () => {
    // This would be implemented with the actual export function
    console.log('Export requested:', exportFormat);
  }, [exportFormat]);

  const handleImport = useCallback(async (file: File) => {
    // This would be implemented with the actual import function
    console.log('Import requested:', file.name);
  }, []);

  return (
    <div className="space-y-6">
      {/* Search & Filters */}
      <Card className="p-4">
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search URL, domain, sender, signals..."
              value={filters.query}
              onChange={(e) => handleFilterChange('query', e.target.value)}
              className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              aria-label="Search history"
            />
          </div>

          <div className="flex flex-wrap gap-2 w-full sm:w-auto">
            <Select
              options={[
                { value: '', label: 'All Risk Levels' },
                ...RISK_LEVELS.map(l => ({ value: l, label: l })),
              ]}
              value={filters.level}
              onChange={(e) => handleFilterChange('level', e.target.value as RiskLevel | '')}
              placeholder="Risk Level"
              className="w-40"
            />
            <Select
              options={[
                { value: '', label: 'All Sources' },
                ...SOURCES.map(s => ({ value: s, label: SOURCE_LABELS[s] })),
              ]}
              value={filters.source}
              onChange={(e) => handleFilterChange('source', e.target.value as HistoryEntry['source'] | '')}
              placeholder="Source"
              className="w-40"
            />
            <Select
              options={[
                { value: '', label: 'All Channels' },
                ...CHANNELS.map(c => ({ value: c, label: CHANNEL_LABELS[c] })),
              ]}
              value={filters.channel}
              onChange={(e) => handleFilterChange('channel', e.target.value as ChannelType | '')}
              placeholder="Channel"
              className="w-40"
            />
            <Select
              options={[
                { value: '', label: 'All Domains' },
                ...uniqueDomains.map(d => ({ value: d, label: d })),
              ]}
              value={filters.domain}
              onChange={(e) => handleFilterChange('domain', e.target.value)}
              placeholder="Domain"
              className="w-48"
            />
          </div>

          <div className="flex gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
              className={clsx(showAdvancedFilters && 'bg-blue-50 dark:bg-blue-900/30')}
            >
              <Filter className="w-4 h-4 mr-1" />
              Advanced
            </Button>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="w-4 h-4 mr-1" />
                Clear
              </Button>
            )}
            <div className="flex items-center gap-1">
              <Download className="w-4 h-4 text-gray-500" />
              <Select
                options={[
                  { value: 'json', label: 'JSON' },
                  { value: 'csv', label: 'CSV' },
                ]}
                value={exportFormat}
                onChange={(e) => setExportFormat(e.target.value as 'json' | 'csv')}
                className="w-24 text-sm py-1.5"
              />
              <Button variant="secondary" size="sm" onClick={handleExport} icon={<Upload className="w-4 h-4" />}>
                Export
              </Button>
              <input
                type="file"
                accept=".json,.csv"
                className="hidden"
                id="import-file"
                onChange={(e) => e.target.files?.[0] && handleImport(e.target.files[0])}
              />
              <Button variant="ghost" size="sm" onClick={() => document.getElementById('import-file')?.click()}>
                Import
              </Button>
            </div>
          </div>
        </div>

        {/* Advanced Filters */}
        {showAdvancedFilters && (
          <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Input
              label="From Date"
              type="date"
              value={filters.from ? format(filters.from as number, 'yyyy-MM-dd') : ''}
              onChange={(e) => handleFilterChange('from', e.target.value ? new Date(e.target.value).getTime() : '')}
            />
            <Input
              label="To Date"
              type="date"
              value={filters.to ? format(filters.to as number, 'yyyy-MM-dd') : ''}
              onChange={(e) => handleFilterChange('to', e.target.value ? new Date(e.target.value).getTime() : '')}
            />
          </div>
        )}
      </Card>

      {/* Results Table */}
      <Card className="p-0">
        <VirtualizedTable
          data={entries}
          columns={createHistoryColumns(onRowClick ? (e) => { setSelectedEntry(e); onRowClick?.(e); } : undefined)}
          height={500}
          rowHeight={48}
          loading={loading}
          emptyMessage="No history entries match your filters"
        />
      </Card>

      {/* Case Detail Modal */}
      {selectedEntry && (
        <CaseDetailModal
          entry={selectedEntry}
          onClose={() => setSelectedEntry(null)}
        />
      )}
    </div>
  );
}

interface CaseDetailModalProps {
  entry: HistoryEntry;
  onClose: () => void;
}

function CaseDetailModal({ entry, onClose }: CaseDetailModalProps) {
  const formatMs = (ms: number) => `${ms}ms`;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="case-detail-title"
    >
      <div
        className="bg-white dark:bg-gray-900 rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-gray-200 dark:border-gray-700 sticky top-0 bg-white dark:bg-gray-900 z-10">
          <div>
            <h2 id="case-detail-title" className="text-xl font-semibold text-gray-900 dark:text-gray-100">
              Case Details
            </h2>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {formatRelativeTime(entry.timestamp)} • Score: {entry.score} • {entry.action.toUpperCase()}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <RiskBadge level={entry.level} size="md" />
            <ActionBadge action={entry.action} size="md" />
            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-500"
              aria-label="Close"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Summary */}
          <Card variant="bordered">
            <CardHeader>
              <CardTitle>Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <StatItem label="URL" value={truncateUrl(entry.url, 60)} fullWidth />
                <StatItem label="Domain" value={entry.registrableDomain} />
                <StatItem label="Channel" value={CHANNEL_LABELS[entry.channel]} />
                <StatItem label="Source" value={SOURCE_LABELS[entry.source]} />
                <StatItem label="Score" value={`${entry.score}/100`} />
                <StatItem label="Latency" value={formatMs(entry.latencyMs)} />
                <StatItem label="Privacy" value={entry.privacyMode} />
                <StatItem label="Time" value={new Date(entry.timestamp).toLocaleString()} />
              </div>
              {entry.sender && (
                <StatItem label="Sender" value={entry.sender} fullWidth />
              )}
            </CardContent>
          </Card>

          {/* Signals */}
          <Card variant="bordered">
            <CardHeader>
              <CardTitle>Detection Signals ({entry.signals.length})</CardTitle>
              <CardDescription>Each signal contributes to the final risk score</CardDescription>
            </CardHeader>
            <CardContent>
              <SignalTable signals={entry.signals} />
            </CardContent>
          </Card>

          {/* URL Analysis */}
          {entry.urlAnalysis && entry.urlAnalysis.length > 0 && (
            <Card variant="bordered">
              <CardHeader>
                <CardTitle>URL Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {entry.urlAnalysis.map((url, i) => (
                    <div key={i} className="p-4 rounded-lg bg-gray-50 dark:bg-gray-800/50 border border-gray-200 dark:border-gray-700">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-sm truncate max-w-[400px]" title={url.url}>
                          {url.url}
                        </span>
                        <RiskBadge level={url.https ? 'Low' : 'Medium'} size="sm" />
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
                        <StatItem label="Host" value={url.host} />
                        <StatItem label="TLD" value={url.tld} />
                        <StatItem label="HTTPS" value={url.https ? 'Yes' : 'No'} />
                        <StatItem label="Length" value={url.length.toString()} />
                        {url.age_days !== undefined && <StatItem label="Age" value={`${url.age_days} days`} />}
                        {url.subdomains.length > 0 && (
                          <StatItem label="Subdomains" value={url.subdomains.join(', ')} fullWidth />
                        )}
                        {url.redirects.length > 0 && (
                          <StatItem label="Redirects" value={url.redirects.length.toString()} />
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Explanation */}
          <Card variant="bordered">
            <CardHeader>
              <CardTitle>Full Explanation</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="prose prose-sm dark:prose-invert max-w-none whitespace-pre-wrap">
                {entry.explanation}
              </div>
            </CardContent>
          </Card>

          {/* Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Actions</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-3">
              <Button
                variant="secondary"
                onClick={() => navigator.clipboard.writeText(entry.url)}
              >
                Copy URL
              </Button>
              <Button
                variant="secondary"
                onClick={() => navigator.clipboard.writeText(entry.explanation)}
              >
                Copy Explanation
              </Button>
              <Button variant="ghost" onClick={() => { /* Mark false positive */ }}>
                Mark False Positive
              </Button>
              <Button variant="ghost" onClick={() => { /* Report */ }}>
                Report
              </Button>
              <Button variant="ghost" onClick={() => { /* Allowlist domain */ }}>
                Allowlist Domain
              </Button>
              <Button variant="danger" onClick={() => { /* Delete */ }}>
                Delete
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function StatItem({ label, value, fullWidth = false }: { label: string; value: string; fullWidth?: boolean }) {
  return (
    <div className={clsx('flex flex-col gap-1', fullWidth && 'sm:col-span-2 lg:col-span-4')}>
      <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">{label}</span>
      <span className="text-sm text-gray-900 dark:text-gray-100 font-mono break-all">{value}</span>
    </div>
  );
}

function format(date: number, fmt: string): string {
  return new Date(date).toLocaleString();
}