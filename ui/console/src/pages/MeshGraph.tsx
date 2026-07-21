import { createEffect, createSignal, onCleanup, onMount } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { forceSimulation, forceLink, forceManyBody, forceCenter, type SimulationNodeDatum, type SimulationLinkDatum } from "d3-force";
import { Network } from "lucide-solid";
import { listRoutes } from "../api/client";
import { theme } from "../theme/store";
import { EmptyState } from "../components/ui";
import { GlowDot } from "../components/GlowDot";
import { Reveal } from "../components/Reveal";

interface Node extends SimulationNodeDatum {
  id: string;
  label: string;
}

interface Link extends SimulationLinkDatum<Node> {
  healthy: boolean;
  name: string;
}

export default function MeshGraph() {
  let svgRef!: SVGSVGElement;
  let containerRef!: HTMLDivElement;

  const routesQuery = createQuery(() => ({
    queryKey: ["routes"],
    queryFn: listRoutes,
    refetchInterval: 5000,
  }));

  // Pan/zoom state, independent of the simulation tick so dragging/
  // scrolling stays smooth even while nodes are still settling. Built on
  // Pointer Events rather than mouse events so the same code path drives
  // mouse drag, single-finger touch pan, and two-finger pinch-zoom — no
  // separate touch handlers to keep in sync.
  const [transform, setTransform] = createSignal({ x: 0, y: 0, k: 1 });
  let dragging = false;
  let dragStart = { x: 0, y: 0 };
  let panStart = { x: 0, y: 0 };
  const activePointers = new Map<number, { x: number; y: number }>();
  let pinchStartDist = 0;
  let pinchStartK = 1;

  const pinchDistance = (): number => {
    const pts = [...activePointers.values()];
    if (pts.length < 2) return 0;
    return Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
  };

  onMount(() => {
    if (!containerRef) return;

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const t = transform();
      const delta = e.deltaY > 0 ? 0.9 : 1.1;
      const k = Math.min(3, Math.max(0.4, t.k * delta));
      setTransform({ ...t, k });
    };

    const onPointerDown = (e: PointerEvent) => {
      containerRef.setPointerCapture(e.pointerId);
      activePointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (activePointers.size === 1) {
        dragging = true;
        dragStart = { x: e.clientX, y: e.clientY };
        const t = transform();
        panStart = { x: t.x, y: t.y };
      } else if (activePointers.size === 2) {
        dragging = false;
        pinchStartDist = pinchDistance();
        pinchStartK = transform().k;
      }
    };

    const onPointerMove = (e: PointerEvent) => {
      if (!activePointers.has(e.pointerId)) return;
      activePointers.set(e.pointerId, { x: e.clientX, y: e.clientY });

      if (activePointers.size === 2) {
        const dist = pinchDistance();
        if (pinchStartDist > 0) {
          const k = Math.min(3, Math.max(0.4, pinchStartK * (dist / pinchStartDist)));
          setTransform({ ...transform(), k });
        }
        return;
      }
      if (!dragging) return;
      const t = transform();
      setTransform({ ...t, x: panStart.x + (e.clientX - dragStart.x), y: panStart.y + (e.clientY - dragStart.y) });
    };

    const onPointerUp = (e: PointerEvent) => {
      activePointers.delete(e.pointerId);
      if (activePointers.size === 1) {
        // Resume single-finger pan from here rather than jumping back to
        // the original two-finger drag origin.
        const [remaining] = activePointers.values();
        dragging = true;
        dragStart = { x: remaining.x, y: remaining.y };
        const t = transform();
        panStart = { x: t.x, y: t.y };
      } else if (activePointers.size === 0) {
        dragging = false;
      }
    };

    containerRef.addEventListener("wheel", onWheel, { passive: false });
    containerRef.addEventListener("pointerdown", onPointerDown);
    containerRef.addEventListener("pointermove", onPointerMove);
    containerRef.addEventListener("pointerup", onPointerUp);
    containerRef.addEventListener("pointercancel", onPointerUp);
    onCleanup(() => {
      containerRef.removeEventListener("wheel", onWheel);
      containerRef.removeEventListener("pointerdown", onPointerDown);
      containerRef.removeEventListener("pointermove", onPointerMove);
      containerRef.removeEventListener("pointerup", onPointerUp);
      containerRef.removeEventListener("pointercancel", onPointerUp);
    });
  });

  let lastNodes: Node[] = [];
  let lastLinks: Link[] = [];

  createEffect(() => {
    const routes = routesQuery.data;
    if (!routes || !svgRef) return;

    const nodeMap = new Map<string, Node>();
    const links: Link[] = [];

    for (const r of routes) {
      const srcId = `${r.source.instance}@${r.source.cluster}`;
      const tgtId = `${r.target.instance}@${r.target.cluster}`;
      if (!nodeMap.has(srcId)) nodeMap.set(srcId, { id: srcId, label: r.source.instance });
      if (!nodeMap.has(tgtId)) nodeMap.set(tgtId, { id: tgtId, label: r.target.instance });
      links.push({ source: srcId, target: tgtId, healthy: r.status.healthy, name: r.name });
    }

    const nodes = Array.from(nodeMap.values());
    lastNodes = nodes;
    lastLinks = links;
    if (nodes.length === 0) {
      svgRef.innerHTML = "";
      return;
    }

    const width = svgRef.clientWidth || 600;
    const height = svgRef.clientHeight || 500;

    const sim = forceSimulation<Node>(nodes)
      .force("link", forceLink<Node, Link>(links).id((d) => d.id).distance(130))
      .force("charge", forceManyBody().strength(-320))
      .force("center", forceCenter(width / 2, height / 2));

    const dark = theme() === "dark";
    sim.on("tick", () => render(svgRef, nodes, links, dark, transform()));

    onCleanup(() => sim.stop());
  });

  // Re-render on pan/zoom without waiting for the next simulation tick —
  // the simulation settles quickly and then goes idle, so panning after
  // that point needs its own trigger.
  createEffect(() => {
    const t = transform();
    if (!svgRef || lastNodes.length === 0) return;
    render(svgRef, lastNodes, lastLinks, theme() === "dark", t);
  });

  return (
    <div>
      <div class="mb-6">
        <h1 class="font-display text-2xl font-bold text-gray-900 dark:text-gray-100">Service Mesh</h1>
        <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Live topology of routes between instances — scroll or pinch to zoom, drag to pan.
        </p>
      </div>

      <Reveal>
        <div
          ref={containerRef}
          class="relative border border-gray-200 dark:border-white/[0.08] rounded-2xl bg-white dark:bg-white/[0.02] shadow-sm dark:shadow-none overflow-hidden cursor-grab active:cursor-grabbing select-none touch-none"
          style={{ height: "500px" }}
        >
          {routesQuery.isLoading && (
            <div class="absolute inset-0 flex items-center justify-center text-sm text-gray-400 dark:text-gray-500">
              Loading topology…
            </div>
          )}
          {routesQuery.data && routesQuery.data.length === 0 && (
            <div class="absolute inset-0 flex items-center justify-center">
              <EmptyState icon={Network} title="No routes configured" description="Create a route to see the mesh topology here." />
            </div>
          )}
          <svg ref={svgRef!} width="100%" height="100%" />
        </div>
      </Reveal>

      <div class="mt-3 flex gap-5 text-sm text-gray-600 dark:text-gray-400">
        <GlowDot tone="healthy" label="Healthy" />
        <GlowDot tone="critical" pulse={false} label="Unhealthy" />
      </div>
    </div>
  );
}

function render(svg: SVGSVGElement, nodes: Node[], links: Link[], dark: boolean, t: { x: number; y: number; k: number }) {
  svg.innerHTML = "";

  const ns = "http://www.w3.org/2000/svg";
  const nodeLabelColor = dark ? "#e2e8f0" : "#374151";
  const healthyColor = "#22d3ee";
  const unhealthyColor = "#f87171";
  const nodeFill = dark ? "#818cf8" : "#6366f1";

  const defs = document.createElementNS(ns, "defs");

  // Arrow marker.
  const marker = document.createElementNS(ns, "marker");
  marker.setAttribute("id", "arrow");
  marker.setAttribute("viewBox", "0 0 10 10");
  marker.setAttribute("refX", "20");
  marker.setAttribute("refY", "5");
  marker.setAttribute("markerWidth", "6");
  marker.setAttribute("markerHeight", "6");
  marker.setAttribute("orient", "auto-start-reverse");
  const arrowPath = document.createElementNS(ns, "path");
  arrowPath.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
  arrowPath.setAttribute("fill", dark ? "#94a3b8" : "#666");
  marker.appendChild(arrowPath);
  defs.appendChild(marker);

  // Soft glow filter, reused by healthy edges + node circles.
  const filter = document.createElementNS(ns, "filter");
  filter.setAttribute("id", "mesh-glow");
  filter.setAttribute("x", "-75%");
  filter.setAttribute("y", "-75%");
  filter.setAttribute("width", "250%");
  filter.setAttribute("height", "250%");
  const blur = document.createElementNS(ns, "feGaussianBlur");
  blur.setAttribute("stdDeviation", "3.5");
  blur.setAttribute("result", "glow");
  const merge = document.createElementNS(ns, "feMerge");
  const mergeGlow = document.createElementNS(ns, "feMergeNode");
  mergeGlow.setAttribute("in", "glow");
  const mergeSource = document.createElementNS(ns, "feMergeNode");
  mergeSource.setAttribute("in", "SourceGraphic");
  merge.appendChild(mergeGlow);
  merge.appendChild(mergeSource);
  filter.appendChild(blur);
  filter.appendChild(merge);
  defs.appendChild(filter);
  svg.appendChild(defs);

  const viewport = document.createElementNS(ns, "g");
  viewport.setAttribute("transform", `translate(${t.x},${t.y}) scale(${t.k})`);
  svg.appendChild(viewport);

  const linkEls = new Map<Link, SVGLineElement>();
  const nodeConnections = new Map<string, Set<string>>();

  for (const link of links) {
    const src = link.source as Node;
    const tgt = link.target as Node;
    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", String(src.x ?? 0));
    line.setAttribute("y1", String(src.y ?? 0));
    line.setAttribute("x2", String(tgt.x ?? 0));
    line.setAttribute("y2", String(tgt.y ?? 0));
    line.setAttribute("stroke", link.healthy ? healthyColor : unhealthyColor);
    line.setAttribute("stroke-width", "2");
    line.setAttribute("opacity", link.healthy ? "0.8" : "0.6");
    line.setAttribute("marker-end", "url(#arrow)");
    if (link.healthy) line.setAttribute("filter", "url(#mesh-glow)");
    line.style.transition = "opacity 150ms ease, stroke-width 150ms ease";
    viewport.appendChild(line);
    linkEls.set(link, line);

    for (const id of [src.id, tgt.id]) {
      if (!nodeConnections.has(id)) nodeConnections.set(id, new Set());
    }
    nodeConnections.get(src.id)!.add(tgt.id);
    nodeConnections.get(tgt.id)!.add(src.id);
  }

  for (const node of nodes) {
    const g = document.createElementNS(ns, "g");
    g.style.cursor = "pointer";

    const circle = document.createElementNS(ns, "circle");
    circle.setAttribute("cx", String(node.x ?? 0));
    circle.setAttribute("cy", String(node.y ?? 0));
    circle.setAttribute("r", "12");
    circle.setAttribute("fill", nodeFill);
    circle.setAttribute("stroke", dark ? "#c7d2fe" : "#4338ca");
    circle.setAttribute("stroke-width", "1.5");
    circle.setAttribute("filter", "url(#mesh-glow)");
    circle.style.transformOrigin = `${node.x}px ${node.y}px`;
    circle.style.transition = "transform 150ms ease";

    g.addEventListener("mouseenter", () => {
      circle.style.transform = "scale(1.35)";
      const connected = nodeConnections.get(node.id) ?? new Set();
      for (const [link, el] of linkEls) {
        const src = link.source as Node;
        const tgt = link.target as Node;
        const touches = src.id === node.id || tgt.id === node.id;
        el.style.opacity = touches ? "1" : "0.15";
        el.setAttribute("stroke-width", touches ? "3" : "2");
      }
    });
    g.addEventListener("mouseleave", () => {
      circle.style.transform = "scale(1)";
      for (const [link, el] of linkEls) {
        el.style.opacity = link.healthy ? "0.8" : "0.6";
        el.setAttribute("stroke-width", "2");
      }
    });

    g.appendChild(circle);

    const text = document.createElementNS(ns, "text");
    text.setAttribute("x", String(node.x ?? 0));
    text.setAttribute("y", String((node.y ?? 0) + 26));
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("font-size", "11");
    text.setAttribute("fill", nodeLabelColor);
    text.textContent = node.label;
    g.appendChild(text);

    viewport.appendChild(g);
  }
}
