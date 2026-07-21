// ECharts provider for SolidJS. Manages the chart instance lifecycle
// (init on mount, setOption on signal change, resize on window resize,
// dispose on cleanup). Callers pass an ECharts option object; the
// component handles the rest.
//
// Usage:
//   <EChart option={myOption} height="300px" />

import { onMount, onCleanup, createEffect, type JSX } from "solid-js";
import * as echarts from "echarts";

export interface EChartProps {
  option: echarts.EChartsOption;
  height?: string;
  class?: string;
}

export function EChart(props: EChartProps): JSX.Element {
  let container: HTMLDivElement | undefined;
  let chart: echarts.ECharts | null = null;

  onMount(() => {
    if (!container) return;
    // No ECharts built-in theme name here — every color in this app's
    // chart options (chart-options.ts) is explicit and already
    // theme-aware (callers pass `dark: theme() === "dark"` into the
    // option builders), so layering ECharts' own "dark" theme on top
    // would just fight those explicit overrides.
    chart = echarts.init(container, undefined, { renderer: "canvas" });

    // Responsive resize — ECharts doesn't observe container size
    // changes on its own.
    const resizeObserver = new ResizeObserver(() => {
      chart?.resize();
    });
    resizeObserver.observe(container);

    onCleanup(() => {
      resizeObserver.disconnect();
      chart?.dispose();
      chart = null;
    });
  });

  createEffect(() => {
    if (chart) {
      chart.setOption(props.option, { notMerge: false, lazyUpdate: true });
    }
  });

  return (
    <div
      ref={container}
      class={props.class}
      style={{ width: "100%", height: props.height ?? "300px" }}
    />
  );
}