// Pre-built ECharts option builders for the analytics pages. Each
// function returns a complete ECharts option object so the EChart
// wrapper component just calls setOption — no per-page chart
// configuration logic duplicates across pages.
//
// Design: dark background to match the existing sidebar/theme; the
// chart containers live inside white cards (bg-white rounded-xl)
// so the dark canvas provides contrast for the data series while
// the surrounding card stays light for readability.

import type { EChartsOption } from "echarts";

// --- color tokens (enterprise severity palette) ---

export const chartColors = {
  allow: "#22c55e",
  deny: "#ef4444",
  error: "#f97316",
  warning: "#f59e0b",
  critical: "#dc2626",
  info: "#3b82f6",
  blue: "#3b82f6",
  indigo: "#6366f1",
  purple: "#a855f7",
  orange: "#f97316",
  gray: "#9ca3af",
};

const baseTextStyle = {
  color: "#374151",
  fontFamily: "ui-monospace, monospace",
};

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
  opts?: { yLabel?: string; yUnit?: string },
): EChartsOption {
  return {
    backgroundColor: "transparent",
    textStyle: baseTextStyle,
    grid: baseGrid,
    tooltip: {
      trigger: "axis",
      backgroundColor: "#1f2937",
      borderColor: "#374151",
      textStyle: { color: "#f3f4f6" },
      formatter: (params: any) => {
        const ts = new Date(params[0].value[0]).toLocaleString();
        let html = `<div style="font-size:11px;color:#9ca3af;margin-bottom:4px">${ts}</div>`;
        for (const p of params) {
          html += `<div style="font-size:12px"><span style="color:${p.color}">●</span> ${p.seriesName}: <b>${p.value[1].toFixed(2)}${opts?.yUnit ?? ""}</b></div>`;
        }
        return html;
      },
    },
    legend: {
      show: series.length > 1,
      bottom: 0,
      textStyle: { color: "#6b7280", fontSize: 11 },
    },
    xAxis: {
      type: "time",
      axisLine: { lineStyle: { color: "#e5e7eb" } },
      axisLabel: { color: "#9ca3af", fontSize: 10 },
    },
    yAxis: {
      type: "value",
      name: opts?.yLabel,
      nameTextStyle: { color: "#9ca3af", fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: "#f3f4f6" } },
      axisLabel: { color: "#9ca3af", fontSize: 10 },
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
        ? { areaStyle: { opacity: 0.15, color: s.color } }
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
  opts?: { xLabel?: string; xUnit?: string },
): EChartsOption {
  const categories = buckets.map((b) => `${(b.le * 1000).toFixed(0)}ms`);
  const counts = buckets.map((b) => b.count);
  const maxCount = Math.max(...counts, 1);

  return {
    backgroundColor: "transparent",
    textStyle: baseTextStyle,
    grid: baseGrid,
    tooltip: {
      trigger: "axis",
      backgroundColor: "#1f2937",
      borderColor: "#374151",
      textStyle: { color: "#f3f4f6" },
      formatter: (params: any) => {
        const p = params[0];
        return `<div style="font-size:12px"><b>${p.name}</b><br/>count: ${p.value}</div>`;
      },
    },
    xAxis: {
      type: "category",
      data: categories,
      name: opts?.xLabel ?? "Latency",
      nameTextStyle: { color: "#9ca3af", fontSize: 10 },
      axisLine: { lineStyle: { color: "#e5e7eb" } },
      axisLabel: { color: "#9ca3af", fontSize: 10, rotate: categories.length > 10 ? 45 : 0 },
    },
    yAxis: {
      type: "value",
      name: "Count",
      nameTextStyle: { color: "#9ca3af", fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: "#f3f4f6" } },
      axisLabel: { color: "#9ca3af", fontSize: 10 },
    },
    series: [
      {
        type: "bar",
        data: counts.map((c, i) => ({
          value: c,
          itemStyle: {
            color: i === buckets.length - 1 ? chartColors.error : chartColors.blue,
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

export function donutOption(slices: DonutSlice[]): EChartsOption {
  return {
    backgroundColor: "transparent",
    textStyle: baseTextStyle,
    tooltip: {
      trigger: "item",
      backgroundColor: "#1f2937",
      borderColor: "#374151",
      textStyle: { color: "#f3f4f6" },
      formatter: (p: any) =>
        `<div style="font-size:12px"><b>${p.name}</b><br/>${p.value} (${p.percent}%)</div>`,
    },
    legend: {
      bottom: 0,
      textStyle: { color: "#6b7280", fontSize: 11 },
    },
    series: [
      {
        type: "pie",
        radius: ["45%", "70%"],
        center: ["50%", "45%"],
        avoidLabelOverlap: true,
        label: { show: false },
        labelLine: { show: false },
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

export function waterfallOption(stages: WaterfallStage[]): EChartsOption {
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
    textStyle: baseTextStyle,
    grid: { ...baseGrid, left: 120 },
    tooltip: {
      trigger: "axis",
      backgroundColor: "#1f2937",
      borderColor: "#374151",
      textStyle: { color: "#f3f4f6" },
      formatter: (params: any) => {
        const stage = params[1];
        return `<div style="font-size:12px"><b>${stage.name}</b><br/>${stage.value.toFixed(1)}ms</div>`;
      },
    },
    xAxis: {
      type: "value",
      name: "Cumulative latency (ms)",
      nameTextStyle: { color: "#9ca3af", fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: "#f3f4f6" } },
      axisLabel: { color: "#9ca3af", fontSize: 10 },
    },
    yAxis: {
      type: "category",
      data: categories,
      axisLine: { lineStyle: { color: "#e5e7eb" } },
      axisLabel: { color: "#374151", fontSize: 11 },
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
          itemStyle: { color: s.color ?? chartColors.blue },
        })),
        label: {
          show: true,
          position: "right",
          formatter: (p: any) => `${p.value.toFixed(1)}ms`,
          color: "#6b7280",
          fontSize: 10,
        },
      },
    ],
  };
}