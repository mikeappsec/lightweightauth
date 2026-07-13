// Reusable UI primitives for the enterprise design system.
//
// These components fill the gaps identified in the Phase 7 plan:
// - Skeleton loaders (the existing pages show nothing while data loads)
// - WS-disconnect error state (pages silently show stale data when
//   the WebSocket drops)
// - Severity color tokens (centralised so the Alerts page, Dashboard
//   banner, and Policy Analytics page share one source of truth)
// - Empty-state component (consistent "no data" rendering)

import { type JSX, Show } from "solid-js";
import { ShieldCheck, WifiOff, Inbox } from "lucide-solid";

// --- Skeleton loaders ---

export function SkeletonCard(props: { height?: string }): JSX.Element {
  return (
    <div
      class="bg-white rounded-xl border border-gray-200 shadow-sm animate-pulse"
      style={{ height: props.height ?? "100px" }}
    />
  );
}

export function SkeletonRow(props: { columns?: number }): JSX.Element {
  const cols = props.columns ?? 5;
  return (
    <tr>
      {Array.from({ length: cols }).map(() => (
        <td class="px-4 py-3">
          <div class="h-3 bg-gray-100 rounded animate-pulse" style={{ width: `${60 + Math.random() * 30}%` }} />
        </td>
      ))}
    </tr>
  );
}

export function SkeletonTable(props: { rows?: number; columns?: number }): JSX.Element {
  return (
    <div class="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <table class="w-full text-sm">
        <tbody class="divide-y divide-gray-50">
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
      <div class="flex items-center gap-2 bg-red-50 border border-red-200 rounded-lg px-4 py-2.5 mb-4">
        <WifiOff size={16} class="text-red-500" />
        <span class="text-sm text-red-700 font-medium">
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
      <Icon size={40} class="mx-auto text-gray-300 mb-3" />
      <p class="text-sm font-medium text-gray-600">{props.title}</p>
      <Show when={props.description}>
        <p class="text-xs text-gray-400 mt-1">{props.description}</p>
      </Show>
    </div>
  );
}

// --- Severity color tokens ---

export const severityTokens: Record<string, { bg: string; text: string; badge: string; dot: string }> = {
  critical: {
    bg: "bg-red-50",
    text: "text-red-700",
    badge: "bg-red-100 text-red-700",
    dot: "bg-red-500",
  },
  warning: {
    bg: "bg-amber-50",
    text: "text-amber-700",
    badge: "bg-amber-100 text-amber-700",
    dot: "bg-amber-500",
  },
  info: {
    bg: "bg-blue-50",
    text: "text-blue-700",
    badge: "bg-blue-100 text-blue-700",
    dot: "bg-blue-500",
  },
};

export function severityBadgeClass(severity: string): string {
  return severityTokens[severity]?.badge ?? "bg-gray-100 text-gray-600";
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
    <div class={`bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden ${props.class ?? ""}`}>
      <Show when={props.title || props.action}>
        <div class="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <div>
            <Show when={props.title}>
              <h2 class="text-sm font-semibold text-gray-900">{props.title}</h2>
            </Show>
            <Show when={props.subtitle}>
              <p class="text-xs text-gray-500 mt-0.5">{props.subtitle}</p>
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
      blue: "text-blue-700",
      green: "text-green-700",
      red: "text-red-700",
      orange: "text-orange-700",
      purple: "text-purple-700",
      indigo: "text-indigo-700",
      gray: "text-gray-700",
    };
    return map[props.accent ?? "gray"] ?? map.gray;
  };

  return (
    <div class="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
      <p class="text-[10px] font-medium text-gray-500 uppercase tracking-wide">{props.label}</p>
      <div class="flex items-baseline gap-1 mt-1">
        <span class={`text-2xl font-bold ${accentClass()}`}>{props.value}</span>
        <Show when={props.unit}>
          <span class="text-xs text-gray-400">{props.unit}</span>
        </Show>
      </div>
      <Show when={props.trend && props.trendValue}>
        <div class="flex items-center gap-1 mt-1 text-[10px]">
          <span class={
            props.trend === "up" ? "text-green-600" :
            props.trend === "down" ? "text-red-600" :
            "text-gray-400"
          }>
            {props.trend === "up" ? "↑" : props.trend === "down" ? "↓" : "→"}
            {" "}{props.trendValue}
          </span>
        </div>
      </Show>
    </div>
  );
}