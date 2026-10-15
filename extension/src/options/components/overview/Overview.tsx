import React, { useMemo } from 'react';
import { Signal, RiskLevel, ActionType, ChannelType } from '@shared/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './Card';
import { RiskBadge, ActionBadge } from './Badge';
import { VirtualizedTable, createHistoryColumns, SignalTable } from './Table';
import {
  RiskDistributionChart, DailyTrendChart, ChannelBreakdownChart,
  TopItemsChart, ScoreDistributionChart,
  RiskDistributionTable, DailyTrendTable, ChannelBreakdownTable,
  RiskDistributionData, TrendDataPoint, ChannelDataPoint, TopItemData, ScoreDistributionData
} from './Charts';
import { formatRelativeTime, truncateUrl, RISK_LEVEL_COLORS, CHANNEL_LABELS, SOURCE_LABELS } from '../hooks/useSettings';
import { format } from 'date-fns';
import { clsx } from 'clsx';

interface OverviewProps {
  entries: HistoryEntry[];
  stats: HistoryStats | null;
  onRowClick?: (entry: HistoryEntry) => void;
}

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

interface HistoryStats {
  total: number;
  byLevel: Record<RiskLevel, number>;
  bySource: Record<HistoryEntry['source'], number>;
  byChannel: Record<ChannelType, number>;
  avgScore: number;
  todayCount: number;
  thisWeekCount: number;
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

export function Overview({ entries, stats, onRowClick }: OverviewProps) {
  const riskDistribution = useMemo((): RiskDistributionData[] => {
    if (!stats) return [];
    return [
      { name: 'Critical', value: stats.byLevel.Critical, color: RISK_LEVEL_COLORS.Critical },
      { name: 'High', value: stats.byLevel.High, color: RISK_LEVEL_COLORS.High },
      { name: 'Medium', value: stats.byLevel.Medium, color: RISK_LEVEL_COLORS.Medium },
      { name: 'Low', value: stats.byLevel.Low, color: RISK_LEVEL_COLORS.Low },
    ];
  }, [stats]);

  const dailyTrend = useMemo((): TrendDataPoint[] => {
    // Generate last 7 days from entries
    const days: TrendDataPoint[] = [];
    const now = Date.now();
    for (let i = 6; i >= 0; i--) {
      const dayStart = new Date(now - i * 24 * 60 * 60 * 1000);
      dayStart.setHours(0, 0, 0, 0);
      const dayEnd = dayStart.getTime() + 24 * 60 * 60 * 1000;
      const dayEntries = entries.filter(e => e.timestamp >= dayStart.getTime() && e.timestamp < dayEnd);
      days.push({
        date: format(dayStart, 'yyyy-MM-dd'),
        checked: dayEntries.length,
        blocked: dayEntries.filter(e => e.action === 'block').length,
        warned: dayEntries.filter(e => e.action === 'warn').length,
        allowed: dayEntries.filter(e => e.action === 'allow').length,
      });
    }
    return days;
  }, [entries]);

  const channelBreakdown = useMemo((): ChannelDataPoint[] => {
    if (!stats) return [];
    return [
      { name: 'Email', value: stats.byChannel.email, color: '#3b82f6' },
      { name: 'SMS', value: stats.byChannel.sms, color: '#10b981' },
      { name: 'Social', value: stats.byChannel.social, color: '#8b5cf6' },
      { name: 'Direct URL', value: stats.byChannel.url, color: '#f59e0b' },
    ];
  }, [stats]);

  const topSignals = useMemo((): TopItemData[] => {
    const signalCounts: Record<string, number> = {};
    entries.forEach(entry => {
      entry.signals.forEach(signal => {
        signalCounts[signal.label] = (signalCounts[signal.label] || 0) + 1;
      });
    });
    return Object.entries(signalCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([name, count]) => ({ name, count, percentage: (count / entries.length) * 100 }));
  }, [entries]);

  const topDomains = useMemo((): TopItemData[] => {
    const domainCounts: Record<string, number> = {};
    entries.forEach(entry => {
      domainCounts[entry.registrableDomain] = (domainCounts[entry.registrableDomain] || 0) + 1;
    });
    return Object.entries(domainCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([name, count]) => ({ name, count, percentage: (count / entries.length) * 100 }));
  }, [entries]);

  const scoreDistribution = useMemo((): ScoreDistributionData[] => {
    const ranges = [
      { range: '0-20', min: 0, max: 20 },
      { range: '21-40', min: 21, max: 40 },
      { range: '41-60', min: 41, max: 60 },
      { range: '61-80', min: 61, max: 80 },
      { range: '81-100', min: 81, max: 100 },
    ];
    return ranges.map(({ range, min, max }) => ({
      range,
      count: entries.filter(e => e.score >= min && e.score <= max).length,
    }));
  }, [entries]);

  const recentCases = useMemo(() => entries.slice(0, 10), [entries]);

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          title="Total Checked"
          value={stats?.total || 0}
          subtitle={stats?.todayCount !== undefined ? `${stats.todayCount} today` : undefined}
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
          color="blue"
        />
        <KPICard
          title="Blocked"
          value={stats?.byLevel.Critical ? stats.byLevel.Critical + stats.byLevel.High : 0}
          subtitle="High & Critical"
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>}
          color="red"
        />
        <KPICard
          title="Warned"
          value={stats?.byLevel.Medium || 0}
          subtitle="Medium risk"
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>}
          color="amber"
        />
        <KPICard
          title="Avg Score"
          value={stats?.avgScore || 0}
          subtitle={stats?.thisWeekCount !== undefined ? `${stats.thisWeekCount} this week` : undefined}
          icon={<svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" /></svg>}
          color="purple"
        />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <RiskDistributionChart data={riskDistribution} />
        <DailyTrendChart data={dailyTrend} />
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ChannelBreakdownChart data={channelBreakdown} />
        <TopItemsChart
          data={topSignals}
          title="Top Signals"
          description="Most common detection signals"
        />
        <TopItemsChart
          data={topDomains}
          title="Top Domains"
          description="Most analyzed domains"
          color="#8b5cf6"
        />
      </div>

      {/* Score Distribution & Recent Cases */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ScoreDistributionChart data={scoreDistribution} />

        <Card>
          <CardHeader>
            <CardTitle>Recent Cases</CardTitle>
            <CardDescription>Latest 10 analyzed items</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <VirtualizedTable
              data={recentCases}
              columns={createHistoryColumns(onRowClick)}
              height={300}
              rowHeight={48}
              emptyMessage="No recent cases"
            />
          </CardContent>
        </Card>
      </div>

      {/* Accessible Table Alternatives */}
      <details className="group">
        <summary className="cursor-pointer text-sm font-medium text-gray-600 dark:text-gray-400 p-2 hover:text-gray-900 dark:hover:text-gray-100 flex items-center gap-2">
          <svg className="w-4 h-4 transition-transform group-open:rotate-90" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
          View accessible table alternatives
        </summary>
        <div className="mt-4 space-y-6 p-4 bg-gray-50 dark:bg-gray-800/50 rounded-lg border border-gray-200 dark:border-gray-700">
          <div>
            <h3 className="font-medium text-gray-900 dark:text-gray-100 mb-2">Risk Distribution</h3>
            <RiskDistributionTable data={riskDistribution} />
          </div>
          <div>
            <h3 className="font-medium text-gray-900 dark:text-gray-100 mb-2">Daily Trend</h3>
            <DailyTrendTable data={dailyTrend} />
          </div>
          <div>
            <h3 className="font-medium text-gray-900 dark:text-gray-100 mb-2">Channel Breakdown</h3>
            <ChannelBreakdownTable data={channelBreakdown} />
          </div>
        </div>
      </details>
    </div>
  );
}

function KPICard({
  title,
  value,
  subtitle,
  icon,
  color,
}: {
  title: string;
  value: number | string;
  subtitle?: string;
  icon: React.ReactNode;
  color: 'blue' | 'red' | 'amber' | 'purple';
}) {
  const colors = {
    blue: 'bg-blue-500',
    red: 'bg-red-500',
    amber: 'bg-amber-500',
    purple: 'bg-purple-500',
  };

  return (
    <Card className="p-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
          <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-gray-100 tabular-nums">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
          {subtitle && (
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{subtitle}</p>
          )}
        </div>
        <div className={clsx('p-2 rounded-lg', colors[color])}>
          {icon}
        </div>
      </div>
    </Card>
  );
}