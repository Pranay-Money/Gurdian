import React from 'react';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, ComposedChart
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from './Card';
import { format } from 'date-fns';

interface ChartContainerProps {
  title: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
}

export function ChartContainer({ title, description, children, className }: ChartContainerProps) {
  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{description}</p>}
      </CardHeader>
      <CardContent>
        <div className="h-64 w-full" role="img" aria-label={title}>
          {children}
        </div>
      </CardContent>
    </Card>
  );
}

// Color palette for charts (WCAG AA compliant)
export const CHART_COLORS = {
  primary: '#3b82f6',
  success: '#10b981',
  warning: '#f59e0b',
  danger: '#ef4444',
  info: '#06b6d4',
  purple: '#8b5cf6',
  gray: '#6b7280',
};

export const RISK_COLORS = {
  Low: '#10b981',
  Medium: '#f59e0b',
  High: '#ef4444',
  Critical: '#7c2d12',
};

export const CHANNEL_COLORS = {
  email: '#3b82f6',
  sms: '#10b981',
  social: '#8b5cf6',
  url: '#f59e0b',
};

interface RiskDistributionData {
  name: string;
  value: number;
  color: string;
}

interface RiskDistributionChartProps {
  data: RiskDistributionData[];
}

export function RiskDistributionChart({ data }: RiskDistributionChartProps) {
  return (
    <ChartContainer title="Risk Distribution" description="Cases by risk level">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={100}
            fill="#8884d8"
            paddingAngle={2}
            dataKey="value"
            nameKey="name"
            label={({ name, value, percent }) => `${name}: ${value} (${(percent * 100).toFixed(1)}%)`}
            labelLine={false}
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value: number) => [value, 'cases']}
            labelFormatter={(name: string) => name}
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

interface TrendDataPoint {
  date: string;
  checked: number;
  blocked: number;
  warned: number;
  allowed: number;
}

interface DailyTrendChartProps {
  data: TrendDataPoint[];
}

export function DailyTrendChart({ data }: DailyTrendChartProps) {
  return (
    <ChartContainer title="Daily Trend (7 days)" description="Cases over time">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey="date"
            tickFormatter={(date) => format(new Date(date), 'MMM d')}
            tick={{ fill: '#6b7280', fontSize: 12 }}
            axisLine={{ stroke: '#e5e7eb' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: '#6b7280', fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
            labelFormatter={(date) => format(new Date(date), 'MMMM d, yyyy')}
          />
          <Legend />
          <Line
            type="monotone"
            dataKey="checked"
            name="Checked"
            stroke={CHART_COLORS.primary}
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
          <Line
            type="monotone"
            dataKey="blocked"
            name="Blocked"
            stroke={CHART_COLORS.danger}
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
          <Line
            type="monotone"
            dataKey="warned"
            name="Warned"
            stroke={CHART_COLORS.warning}
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
          <Line
            type="monotone"
            dataKey="allowed"
            name="Allowed"
            stroke={CHART_COLORS.success}
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

interface ChannelDataPoint {
  name: string;
  value: number;
  color: string;
}

interface ChannelBreakdownChartProps {
  data: ChannelDataPoint[];
}

export function ChannelBreakdownChart({ data }: ChannelBreakdownChartProps) {
  return (
    <ChartContainer title="Channel Breakdown" description="Cases by source channel">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
          <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis
            dataKey="name"
            type="category"
            tick={{ fill: '#6b7280', fontSize: 12 }}
            axisLine={false}
            tickLine={false}
            width={80}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
            formatter={(value: number) => [value, 'cases']}
          />
          <Bar dataKey="value" radius={[0, 4, 4, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

interface TopItemData {
  name: string;
  count: number;
  percentage: number;
}

interface TopItemsChartProps {
  data: TopItemData[];
  title: string;
  description?: string;
  color?: string;
}

export function TopItemsChart({ data, title, description, color = CHART_COLORS.primary }: TopItemsChartProps) {
  return (
    <ChartContainer title={title} description={description}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
          <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis
            dataKey="name"
            type="category"
            tick={{ fill: '#6b7280', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={200}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
            formatter={(value: number) => [value, 'occurrences']}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} fill={color}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

interface ScoreDistributionData {
  range: string;
  count: number;
}

interface ScoreDistributionChartProps {
  data: ScoreDistributionData[];
}

export function ScoreDistributionChart({ data }: ScoreDistributionChartProps) {
  return (
    <ChartContainer title="Score Distribution" description="Cases by risk score range">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
          <XAxis
            dataKey="range"
            tick={{ fill: '#6b7280', fontSize: 11 }}
            axisLine={{ stroke: '#e5e7eb' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: '#6b7280', fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
            }}
            formatter={(value: number) => [value, 'cases']}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} fill={CHART_COLORS.primary} />
        </BarChart>
      </ResponsiveContainer>
    </ChartContainer>
  );
}

// Accessible table alternatives for charts
export function RiskDistributionTable({ data }: RiskDistributionChartProps) {
  return (
    <table className="w-full text-sm" role="table">
      <thead>
        <tr className="border-b border-gray-200 dark:border-gray-700">
          <th className="text-left py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Risk Level</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Count</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Percentage</th>
        </tr>
      </thead>
      <tbody>
        {data.map((item) => (
          <tr key={item.name} className="border-b border-gray-100 dark:border-gray-700/50">
            <td className="py-2 px-3">
              <RiskBadge level={item.name as any} size="sm" showLabel />
            </td>
            <td className="text-right py-2 px-3 font-mono tabular-nums">{item.value}</td>
            <td className="text-right py-2 px-3 text-gray-500 dark:text-gray-400">
              {((item.value / data.reduce((sum, d) => sum + d.value, 0)) * 100).toFixed(1)}%
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function DailyTrendTable({ data }: DailyTrendChartProps) {
  return (
    <table className="w-full text-sm" role="table">
      <thead>
        <tr className="border-b border-gray-200 dark:border-gray-700">
          <th className="text-left py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Date</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Checked</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Blocked</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Warned</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Allowed</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Total</th>
        </tr>
      </thead>
      <tbody>
        {data.map((item) => (
          <tr key={item.date} className="border-b border-gray-100 dark:border-gray-700/50">
            <td className="py-2 px-3">{format(new Date(item.date), 'MMM d, yyyy')}</td>
            <td className="text-right py-2 px-3 font-mono tabular-nums">{item.checked}</td>
            <td className="text-right py-2 px-3 font-mono tabular-nums text-red-600">{item.blocked}</td>
            <td className="text-right py-2 px-3 font-mono tabular-nums text-amber-600">{item.warned}</td>
            <td className="text-right py-2 px-3 font-mono tabular-nums text-emerald-600">{item.allowed}</td>
            <td className="text-right py-2 px-3 font-mono tabular-nums font-medium">
              {item.checked + item.blocked + item.warned + item.allowed}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function ChannelBreakdownTable({ data }: ChannelBreakdownChartProps) {
  const total = data.reduce((sum, d) => sum + d.value, 0);
  return (
    <table className="w-full text-sm" role="table">
      <thead>
        <tr className="border-b border-gray-200 dark:border-gray-700">
          <th className="text-left py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Channel</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Count</th>
          <th className="text-right py-2 px-3 font-medium text-gray-500 dark:text-gray-400">Percentage</th>
        </tr>
      </thead>
      <tbody>
        {data.map((item) => (
          <tr key={item.name} className="border-b border-gray-100 dark:border-gray-700/50">
            <td className="py-2 px-3">
              <Badge variant="outline" size="sm" style={{ backgroundColor: item.color, borderColor: item.color, color: item.color }}>
                {item.name}
              </Badge>
            </td>
            <td className="text-right py-2 px-3 font-mono tabular-nums">{item.value}</td>
            <td className="text-right py-2 px-3 text-gray-500 dark:text-gray-400">
              {((item.value / total) * 100).toFixed(1)}%
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}