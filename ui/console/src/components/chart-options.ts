// Pre-built ECharts option builders for the analytics pages. Each
// function returns a complete ECharts option object so the EChart
// wrapper component just calls setOption — no per-page chart
// configuration logic duplicates across pages.
//
// Theme-aware: every builder takes a `dark` flag and branches its axis/
// text/tooltip colors accordingly (ECharts renders to canvas, so it can't
// read CSS custom properties directly — callers pass `theme() === "dark"`
// from src/theme/store.ts so charts actually follow the app's light/dark
// toggle instead of the fixed light-axis-colors-on-a-forced-dark-canvas
// mismatch this had before).

import type { EChartsOption } from "echarts";

// --- color tokens (enterprise severity + mission-control palette) ---

export const chartColors = {
  allow: "#22c55e",
  deny: "#ef4444",
  error: "#f97316",
  warning: "#f59e0b",
  critical: "#dc2626",
  info: "#3b82f6",
  blue: "#6366f1",
  live: "#22d3ee",
  indigo: "#6366f1",
  purple: "#a855f7",
  orange: "#f97316",
  gray: "#9ca3af",
};

interface Palette {
  text: string;
  axisLabel: string;
  axisLine: string;
  splitLine: string;
  tooltipBg: string;
  tooltipBorder: string;
  tooltipText: string;
  legendText: string;
}

function palette(dark: boolean): Palette {
  return dark
    ? {
        text: "#cbd5e1",
        axisLabel: "#94a3b8",
        axisLine: "rgba(255,255,255,0.12)",
        splitLine: "rgba(255,255,255,0.06)",
        tooltipBg: "#12141f",
        tooltipBorder: "rgba(255,255,255,0.1)",
        tooltipText: "#f1f5f9",
        legendText: "#94a3b8",
      }
    : {
        text: "#374151",
        axisLabel: "#9ca3af",
        axisLine: "#e5e7eb",
        splitLine: "#f3f4f6",
        tooltipBg: "#1f2937",
        tooltipBorder: "#374151",
        tooltipText: "#f3f4f6",
        legendText: "#6b7280",
      };
}

function baseTextStyle(p: Palette) {
  return { color: p.text, fontFamily: "ui-monospace, monospace" };
}

const baseGrid: EChartsOption["grid"] = {
  left: 50,
  right: 20,
  top: 30,
  bottom: 30,
};

// --- TimeSeries ---

export interface TimeSeriesSeries {
  name: string;
  data: [number, number][]; // [timestamp_ms, value]
  color?: string;
  areaStyle?: boolean;
}

export function timeSeriesOption(
  series: TimeSeriesSeries[],
  opts?: { yLabel?: string; yUnit?: string; dark?: boolean },
): EChartsOption {
  const p = palette(opts?.dark ?? false);
  return {
    backgroundColor: "transparent",
    textStyle: baseTextStyle(p),
    grid: baseGrid,
    tooltip: {
      trigger: "axis",
      backgroundColor: p.tooltipBg,
      borderColor: p.tooltipBorder,
      textStyle: { color: p.tooltipText },
      formatter: (params: any) => {
        const ts = new Date(params[0].value[0]).toLocaleString();
        let html = `<div style="font-size:11px;color:#9ca3af;margin-bottom:4px">${ts}</div>`;
        for (const pt of params) {
          html += `<div style="font-size:12px"><span style="color:${pt.color}">●</span> ${pt.seriesName}: <b>${pt.value[1].toFixed(2)}${opts?.yUnit ?? ""}</b></div>`;
        }
        return html;
      },
    },
    legend: {
      show: series.length > 1,
      bottom: 0,
      textStyle: { color: p.legendText, fontSize: 11 },
    },
    xAxis: {
      type: "time",
      axisLine: { lineStyle: { color: p.axisLine } },
      axisLabel: { color: p.axisLabel, fontSize: 10 },
    },
    yAxis: {
      type: "value",
      name: opts?.yLabel,
      nameTextStyle: { color: p.axisLabel, fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: p.splitLine } },
      axisLabel: { color: p.axisLabel, fontSize: 10 },
    },
    series: series.map((s) => ({
      name: s.name,
      type: "line",
      smooth: true,
      showSymbol: false,
      data: s.data,
      lineStyle: { width: 2, color: s.color },
      itemStyle: { color: s.color },
      ...(s.areaStyle
        ? { areaStyle: { opacity: opts?.dark ? 0.25 : 0.15, color: s.color } }
        : {}),
    })),
  };
}

// --- Histogram (latency distribution) ---

export interface HistogramBucket {
  le: number; // upper bound in seconds
  count: number;
}

export function histogramOption(
  buckets: HistogramBucket[],
  opts?: { xLabel?: string; xUnit?: string; dark?: boolean },
): EChartsOption {
  const p = palette(opts?.dark ?? false);
  const categories = buckets.map((b) => `${(b.le * 1000).toFixed(0)}ms`);
  const counts = buckets.map((b) => b.count);

  return {
    backgroundColor: "transparent",
    textStyle: baseTextStyle(p),
    grid: baseGrid,
    tooltip: {
      trigger: "axis",
      backgroundColor: p.tooltipBg,
      borderColor: p.tooltipBorder,
      textStyle: { color: p.tooltipText },
      formatter: (params: any) => {
        const pt = params[0];
        return `<div style="font-size:12px"><b>${pt.name}</b><br/>count: ${pt.value}</div>`;
      },
    },
    xAxis: {
      type: "category",
      data: categories,
      name: opts?.xLabel ?? "Latency",
      nameTextStyle: { color: p.axisLabel, fontSize: 10 },
      axisLine: { lineStyle: { color: p.axisLine } },
      axisLabel: { color: p.axisLabel, fontSize: 10, rotate: categories.length > 10 ? 45 : 0 },
    },
    yAxis: {
      type: "value",
      name: "Count",
      nameTextStyle: { color: p.axisLabel, fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: p.splitLine } },
      axisLabel: { color: p.axisLabel, fontSize: 10 },
    },
    series: [
      {
        type: "bar",
        data: counts.map((c, i) => ({
          value: c,
          itemStyle: {
            color: i === buckets.length - 1 ? chartColors.error : chartColors.blue,
            borderRadius: [3, 3, 0, 0],
          },
        })),
        barWidth: "70%",
      },
    ],
  };
}

// --- Donut (allow/deny/error breakdown) ---

export interface DonutSlice {
  name: string;
  value: number;
  color?: string;
}

export function donutOption(slices: DonutSlice[], opts?: { dark?: boolean }): EChartsOption {
  const p = palette(opts?.dark ?? false);
  return {
    backgroundColor: "transparent",
    textStyle: baseTextStyle(p),
    tooltip: {
      trigger: "item",
      backgroundColor: p.tooltipBg,
      borderColor: p.tooltipBorder,
      textStyle: { color: p.tooltipText },
      formatter: (pt: any) =>
        `<div style="font-size:12px"><b>${pt.name}</b><br/>${pt.value} (${pt.percent}%)</div>`,
    },
    legend: {
      bottom: 0,
      textStyle: { color: p.legendText, fontSize: 11 },
    },
    series: [
      {
        type: "pie",
        radius: ["45%", "70%"],
        center: ["50%", "45%"],
        avoidLabelOverlap: true,
        label: { show: false },
        labelLine: { show: false },
        itemStyle: {
          borderColor: opts?.dark ? "#0b0d14" : "#ffffff",
          borderWidth: 2,
        },
        data: slices.map((s) => ({
          name: s.name,
          value: s.value,
          itemStyle: { color: s.color },
        })),
      },
    ],
  };
}

// --- Waterfall (policy explain stages) ---

export interface WaterfallStage {
  name: string;
  durationMs: number;
  color?: string;
}

export function waterfallOption(stages: WaterfallStage[], opts?: { dark?: boolean }): EChartsOption {
  const p = palette(opts?.dark ?? false);
  const categories = stages.map((s) => s.name);
  // Waterfall: each stage starts where the previous ended. The
  // "transparent" base series creates the floating effect; the
  // "value" series draws the visible bar on top.
  let cumulative = 0;
  const baseData: number[] = [];
  const valueData: number[] = [];
  for (const s of stages) {
    baseData.push(cumulative);
    valueData.push(s.durationMs);
    cumulative += s.durationMs;
  }

  return {
    backgroundColor: "transparent",
    textStyle: baseTextStyle(p),
    grid: { ...baseGrid, left: 120 },
    tooltip: {
      trigger: "axis",
      backgroundColor: p.tooltipBg,
      borderColor: p.tooltipBorder,
      textStyle: { color: p.tooltipText },
      formatter: (params: any) => {
        const stage = params[1];
        return `<div style="font-size:12px"><b>${stage.name}</b><br/>${stage.value.toFixed(1)}ms</div>`;
      },
    },
    xAxis: {
      type: "value",
      name: "Cumulative latency (ms)",
      nameTextStyle: { color: p.axisLabel, fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: p.splitLine } },
      axisLabel: { color: p.axisLabel, fontSize: 10 },
    },
    yAxis: {
      type: "category",
      data: categories,
      axisLine: { lineStyle: { color: p.axisLine } },
      axisLabel: { color: p.text, fontSize: 11 },
    },
    series: [
      {
        type: "bar",
        stack: "waterfall",
        barWidth: "60%",
        silent: true,
        itemStyle: { borderColor: "transparent", color: "transparent" },
        data: baseData,
      },
      {
        type: "bar",
        stack: "waterfall",
        barWidth: "60%",
        data: stages.map((s) => ({
          value: s.durationMs,
          itemStyle: { color: s.color ?? chartColors.blue, borderRadius: [0, 3, 3, 0] },
        })),
        label: {
          show: true,
          position: "right",
          formatter: (pt: any) => `${pt.value.toFixed(1)}ms`,
          color: p.legendText,
          fontSize: 10,
        },
      },
    ],
  };
}
