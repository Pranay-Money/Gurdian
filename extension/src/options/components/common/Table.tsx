import React, { useMemo, useCallback, useRef, useEffect, useState } from 'react';
import { clsx } from 'clsx';
import { useVirtualizer } from '@tanstack/react-virtual';
import { ColumnDef, flexRender, createColumnHelper } from '@tanstack/react-table';
import { HistoryEntry, Signal, RiskLevel, ActionType, ChannelType } from '@shared/types';
import { Card, CardContent } from './Card';
import { Badge, RiskBadge, ActionBadge } from './Badge';
import { formatRelativeTime, truncateUrl } from '../hooks/useSettings';
import { RISK_LEVEL_COLORS, CHANNEL_LABELS, SOURCE_LABELS } from '../hooks/useSettings';

const columnHelper = createColumnHelper<HistoryEntry>();

interface VirtualizedTableProps {
  data: HistoryEntry[];
  columns: ColumnDef<HistoryEntry>[];
  height?: number;
  rowHeight?: number;
  overscan?: number;
  onRowClick?: (entry: HistoryEntry) => void;
  emptyMessage?: string;
}

export function VirtualizedTable({
  data,
  columns,
  height = 600,
  rowHeight = 56,
  overscan = 5,
  onRowClick,
  emptyMessage = 'No data available',
}: VirtualizedTableProps) {
  const parentRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);

  useEffect(() => {
    if (parentRef.current) {
      setWidth(parentRef.current.clientWidth);
    }
  }, [data.length]);

  const virtualizer = useVirtualizer({
    count: data.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan,
    gap: 0,
  });

  if (data.length === 0) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center h-64">
          <p className="text-gray-500 dark:text-gray-400 text-center">{emptyMessage}</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden">
      <div
        ref={parentRef}
        className="relative"
        style={{ height, width: '100%' }}
        role="grid"
        aria-label="Data table"
      >
        {/* Header */}
        <div
          className={clsx(
            'sticky top-0 z-10 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700',
            'shadow-sm'
          )}
          style={{ width }}
        >
          <div className="flex" style={{ width }}>
            {columns.map((column, i) => (
              <div
                key={column.id}
                className={clsx(
                  'px-4 py-3 text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider',
                  'border-r border-gray-200 dark:border-gray-700 last:border-r-0',
                  'flex-1 min-w-0 overflow-hidden'
                )}
                style={{
                  width: column.getSize(),
                  minWidth: column.getSize(),
                }}
                role="columnheader"
              >
                {flexRender(column.columnDef.header, column.getContext())}
              </div>
            ))}
          </div>
        </div>

        {/* Body */}
        <div
          className="overflow-y-auto"
          style={{ height: `calc(100% - 40px)`, width }}
        >
          <div
            style={{
              height: virtualizer.getTotalSize(),
              width,
              position: 'relative',
            }}
            role="rowgroup"
          >
            {virtualizer.getVirtualItems().map((virtualRow) => (
              <div
                key={virtualRow.key}
                className={clsx(
                  'flex',
                  virtualRow.index % 2 === 0
                    ? 'bg-white dark:bg-gray-800'
                    : 'bg-gray-50 dark:bg-gray-700/50',
                  'border-b border-gray-100 dark:border-gray-700/50',
                  'transition-colors duration-100',
                  onRowClick && 'cursor-pointer hover:bg-blue-50 dark:hover:bg-blue-900/20'
                )}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width,
                  height: virtualRow.size,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
                role="row"
                onClick={onRowClick ? () => onRowClick(data[virtualRow.index]) : undefined}
                tabIndex={onRowClick ? 0 : undefined}
                onKeyDown={onRowClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(data[virtualRow.index]); }} : undefined}
              >
                {columns.map((column) => (
                  <div
                    key={column.id}
                    className={clsx(
                      'px-4 py-3 text-sm text-gray-900 dark:text-gray-100',
                      'border-r border-gray-200 dark:border-gray-700 last:border-r-0',
                      'flex-1 min-w-0 overflow-hidden',
                      'flex items-center'
                    )}
                    style={{
                      width: column.getSize(),
                      minWidth: column.getSize(),
                    }}
                    role="gridcell"
                  >
                    {flexRender(column.columnDef.cell, column.getContext())}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
    </Card>
  );
}

// Pre-built columns for history table
export function createHistoryColumns(
  onRowClick?: (entry: HistoryEntry) => void
): ColumnDef<HistoryEntry>[] {
  return [
    columnHelper.accessor('timestamp', {
      header: 'Time',
      cell: (info) => formatRelativeTime(info.getValue()),
      size: 120,
    }),
    columnHelper.accessor('url', {
      header: 'URL',
      cell: (info) => (
        <span className="font-mono truncate block max-w-[300px]" title={info.getValue()}>
          {truncateUrl(info.getValue(), 60)}
        </span>
      ),
      size: 300,
    }),
    columnHelper.accessor('registrableDomain', {
      header: 'Domain',
      cell: (info) => (
        <span className="font-medium truncate block max-w-[150px]" title={info.getValue()}>
          {info.getValue()}
        </span>
      ),
      size: 180,
    }),
    columnHelper.accessor('level', {
      header: 'Risk',
      cell: (info) => <RiskBadge level={info.getValue()} size="sm" showLabel />,
      size: 100,
    }),
    columnHelper.accessor('action', {
      header: 'Action',
      cell: (info) => <ActionBadge action={info.getValue()} size="sm" />,
      size: 100,
    }),
    columnHelper.accessor('channel', {
      header: 'Channel',
      cell: (info) => (
        <Badge variant="outline" size="sm">
          {CHANNEL_LABELS[info.getValue()] || info.getValue()}
        </Badge>
      ),
      size: 100,
    }),
    columnHelper.accessor('source', {
      header: 'Source',
      cell: (info) => (
        <Badge variant="default" size="sm">
          {SOURCE_LABELS[info.getValue()] || info.getValue()}
        </Badge>
      ),
      size: 100,
    }),
    columnHelper.accessor('score', {
      header: 'Score',
      cell: (info) => (
        <span className="font-mono tabular-nums">{info.getValue()}</span>
      ),
      size: 70,
    }),
  ];
}

interface SignalTableProps {
  signals: Signal[];
}

export function SignalTable({ signals }: SignalTableProps) {
  if (signals.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500 dark:text-gray-400">
        No signals detected
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {signals.map((signal, index) => (
        <div
          key={`${signal.key}-${index}`}
          className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600"
        >
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-bold"
              style={{ backgroundColor: RISK_LEVEL_COLORS[signal.category === 'linguistic' ? 'High' : signal.category === 'structural' ? 'Medium' : 'Low'] }}
            >
              {signal.points > 0 ? '+' : ''}{signal.points}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-gray-900 dark:text-gray-100">{signal.label}</span>
                <Badge variant="outline" size="xs">{signal.category}</Badge>
              </div>
              <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">{signal.reason}</p>
              {signal.evidence.length > 0 && (
                <div className="mt-2 space-y-1">
                  {signal.evidence.map((ev, i) => (
                    <div key={i} className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                      <span className="font-medium">{ev.type}:</span> {ev.value} — {ev.description}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}