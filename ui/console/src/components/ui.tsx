// Reusable UI primitives for the enterprise design system.
//
// These components fill the gaps identified in the Phase 7 plan:
// - Skeleton loaders (the existing pages show nothing while data loads)
// - WS-disconnect error state (pages silently show stale data when
//   the WebSocket drops)
// - Severity color tokens (centralised so the Alerts page, Dashboard
//   banner, and Policy Analytics page share one source of truth)
// - Empty-state component (consistent "no data" rendering)
//
// Re-themed for the "mission control" redesign: dark-mode variants added
// throughout (PolicyAnalytics/PolicyExplain consume these and previously
// had no dark-mode support at all — fixed here, not per-page), rounded-2xl
// + refined hairline borders + hover-lift replacing the flatter
// rounded-xl treatment, numeric KPI values animate via AnimatedNumber.

import { type JSX, Show } from "solid-js";
import { ShieldCheck, WifiOff, Inbox } from "lucide-solid";
import { AnimatedNumber } from "./AnimatedNumber";

// --- Skeleton loaders ---

export function SkeletonCard(props: { height?: string }): JSX.Element {
  return (
    <div
      class="rounded-2xl border border-gray-200 dark:border-white/[0.08] bg-white dark:bg-white/[0.02] overflow-hidden relative"
      style={{ height: props.height ?? "100px" }}
    >
      <div class="absolute inset-0 bg-gradient-to-r from-transparent via-gray-100 dark:via-white/[0.06] to-transparent bg-[length:200%_100%] animate-shimmer" />
    </div>
  );
}

export function SkeletonRow(props: { columns?: number }): JSX.Element {
  const cols = props.columns ?? 5;
  return (
    <tr>
      {Array.from({ length: cols }).map(() => (
        <td class="px-4 py-3">
          <div
            class="h-3 rounded bg-gray-100 dark:bg-white/[0.06] animate-pulse"
            style={{ width: `${60 + Math.random() * 30}%` }}
          />
        </td>
      ))}
    </tr>
  );
}

export function SkeletonTable(props: { rows?: number; columns?: number }): JSX.Element {
  return (
    <div class="rounded-2xl border border-gray-200 dark:border-white/[0.08] bg-white dark:bg-white/[0.02] shadow-sm overflow-hidden">
      <table class="w-full text-sm">
        <tbody class="divide-y divide-gray-50 dark:divide-white/[0.06]">
          {Array.from({ length: props.rows ?? 5 }).map(() => (
            <SkeletonRow columns={props.columns} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

// --- WS-disconnect error state ---

export function WSDisconnectBanner(props: { show: boolean }): JSX.Element {
  return (
    <Show when={props.show}>
      <div class="flex items-center gap-2 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-lg px-4 py-2.5 mb-4 animate-fade-up">
        <WifiOff size={16} class="text-red-500 dark:text-red-400" />
        <span class="text-sm text-red-700 dark:text-red-400 font-medium">
          Real-time connection lost — displaying stale data. Reconnecting…
        </span>
      </div>
    </Show>
  );
}

// --- Empty state ---

export function EmptyState(props: {
  icon?: (p: any) => JSX.Element;
  title: string;
  description?: string;
}): JSX.Element {
  const Icon = props.icon ?? Inbox;
  return (
    <div class="py-16 text-center">
      <div class="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 dark:bg-white/[0.05]">
        <Icon size={22} class="text-gray-400 dark:text-gray-500" />
      </div>
      <p class="text-sm font-medium text-gray-600 dark:text-gray-300">{props.title}</p>
      <Show when={props.description}>
        <p class="text-xs text-gray-400 dark:text-gray-500 mt-1">{props.description}</p>
      </Show>
    </div>
  );
}

// --- Severity color tokens ---

export const severityTokens: Record<string, { bg: string; text: string; badge: string; dot: string }> = {
  critical: {
    bg: "bg-red-50 dark:bg-red-500/10",
    text: "text-red-700 dark:text-red-400",
    badge: "bg-red-100 dark:bg-red-500/15 text-red-700 dark:text-red-400",
    dot: "bg-red-500 dark:bg-red-400",
  },
  warning: {
    bg: "bg-amber-50 dark:bg-amber-500/10",
    text: "text-amber-700 dark:text-amber-400",
    badge: "bg-amber-100 dark:bg-amber-500/15 text-amber-700 dark:text-amber-400",
    dot: "bg-amber-500 dark:bg-amber-400",
  },
  info: {
    bg: "bg-blue-50 dark:bg-blue-500/10",
    text: "text-blue-700 dark:text-blue-400",
    badge: "bg-blue-100 dark:bg-blue-500/15 text-blue-700 dark:text-blue-400",
    dot: "bg-blue-500 dark:bg-blue-400",
  },
};

export function severityBadgeClass(severity: string): string {
  return severityTokens[severity]?.badge ?? "bg-gray-100 dark:bg-white/10 text-gray-600 dark:text-gray-300";
}

// --- Card wrapper (consistent analytics-page container) ---

export function Card(props: {
  title?: string;
  subtitle?: string;
  children: JSX.Element;
  action?: JSX.Element;
  class?: string;
}): JSX.Element {
  return (
    <div
      class={`bg-white dark:bg-white/[0.02] rounded-2xl border border-gray-200 dark:border-white/[0.08] shadow-sm dark:shadow-none overflow-hidden transition-colors ${props.class ?? ""}`}
    >
      <Show when={props.title || props.action}>
        <div class="px-5 py-4 border-b border-gray-100 dark:border-white/[0.06] flex items-center justify-between">
          <div>
            <Show when={props.title}>
              <h2 class="text-sm font-semibold text-gray-900 dark:text-gray-100">{props.title}</h2>
            </Show>
            <Show when={props.subtitle}>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{props.subtitle}</p>
            </Show>
          </div>
          <Show when={props.action}>{props.action}</Show>
        </div>
      </Show>
      {props.children}
    </div>
  );
}

// --- KPI tile (enterprise density) ---

export function KPITile(props: {
  label: string;
  value: string | number;
  unit?: string;
  trend?: "up" | "down" | "flat";
  trendValue?: string;
  accent?: string;
}): JSX.Element {
  const accentClass = () => {
    const map: Record<string, string> = {
      blue: "text-blue-700 dark:text-blue-400",
      green: "text-green-700 dark:text-green-400",
      red: "text-red-700 dark:text-red-400",
      orange: "text-orange-700 dark:text-orange-400",
      purple: "text-purple-700 dark:text-purple-400",
      indigo: "text-indigo-700 dark:text-indigo-400",
      gray: "text-gray-700 dark:text-gray-300",
    };
    return map[props.accent ?? "gray"] ?? map.gray;
  };

  return (
    <div class="bg-white dark:bg-white/[0.02] rounded-2xl border border-gray-200 dark:border-white/[0.08] shadow-sm dark:shadow-none p-4 transition-all hover:-translate-y-0.5 hover:shadow-md dark:hover:border-white/[0.14]">
      <p class="text-[10px] font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide">{props.label}</p>
      <div class="flex items-baseline gap-1 mt-1">
        <span class={`font-display text-2xl font-bold tabular-nums ${accentClass()}`}>
          {typeof props.value === "number" ? <AnimatedNumber value={props.value} /> : props.value}
        </span>
        <Show when={props.unit}>
          <span class="text-xs text-gray-400 dark:text-gray-500">{props.unit}</span>
        </Show>
      </div>
      <Show when={props.trend && props.trendValue}>
        <div class="flex items-center gap-1 mt-1 text-[10px]">
          <span class={
            props.trend === "up" ? "text-green-600 dark:text-green-400" :
            props.trend === "down" ? "text-red-600 dark:text-red-400" :
            "text-gray-400 dark:text-gray-500"
          }>
            {props.trend === "up" ? "↑" : props.trend === "down" ? "↓" : "→"}
            {" "}{props.trendValue}
          </span>
        </div>
      </Show>
    </div>
  );
}
