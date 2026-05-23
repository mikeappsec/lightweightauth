import { createEffect, onCleanup } from "solid-js";
import { createQuery } from "@tanstack/solid-query";
import { forceSimulation, forceLink, forceManyBody, forceCenter, type SimulationNodeDatum, type SimulationLinkDatum } from "d3-force";
import { listRoutes, type Route } from "../api/client";

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

  const routesQuery = createQuery(() => ({
    queryKey: ["routes"],
    queryFn: listRoutes,
    refetchInterval: 5000,
  }));

  createEffect(() => {
    const routes = routesQuery.data;
    if (!routes || !svgRef) return;

    // Build nodes and links from routes.
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
    if (nodes.length === 0) return;

    const width = svgRef.clientWidth || 600;
    const height = svgRef.clientHeight || 400;

    const sim = forceSimulation<Node>(nodes)
      .force("link", forceLink<Node, Link>(links).id((d) => d.id).distance(120))
      .force("charge", forceManyBody().strength(-300))
      .force("center", forceCenter(width / 2, height / 2));

    sim.on("tick", () => render(svgRef, nodes, links, width, height));

    onCleanup(() => sim.stop());
  });

  return (
    <div>
      <h2 class="text-2xl font-bold mb-4">Service Mesh</h2>
      <div class="border rounded bg-white" style={{ height: "500px" }}>
        <svg ref={svgRef!} width="100%" height="100%" />
      </div>
      <div class="mt-3 flex gap-4 text-sm text-gray-600">
        <span class="flex items-center gap-1">
          <span class="inline-block w-3 h-3 rounded-full bg-green-500" /> Healthy
        </span>
        <span class="flex items-center gap-1">
          <span class="inline-block w-3 h-3 rounded-full bg-red-500" /> Unhealthy
        </span>
      </div>
    </div>
  );
}

function render(svg: SVGSVGElement, nodes: Node[], links: Link[], _w: number, _h: number) {
  // Clear previous content.
  svg.innerHTML = "";

  const ns = "http://www.w3.org/2000/svg";

  // Draw marker for arrows.
  const defs = document.createElementNS(ns, "defs");
  const marker = document.createElementNS(ns, "marker");
  marker.setAttribute("id", "arrow");
  marker.setAttribute("viewBox", "0 0 10 10");
  marker.setAttribute("refX", "20");
  marker.setAttribute("refY", "5");
  marker.setAttribute("markerWidth", "6");
  marker.setAttribute("markerHeight", "6");
  marker.setAttribute("orient", "auto-start-reverse");
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
  path.setAttribute("fill", "#666");
  marker.appendChild(path);
  defs.appendChild(marker);
  svg.appendChild(defs);

  // Draw links.
  for (const link of links) {
    const src = link.source as Node;
    const tgt = link.target as Node;
    const line = document.createElementNS(ns, "line");
    line.setAttribute("x1", String(src.x ?? 0));
    line.setAttribute("y1", String(src.y ?? 0));
    line.setAttribute("x2", String(tgt.x ?? 0));
    line.setAttribute("y2", String(tgt.y ?? 0));
    line.setAttribute("stroke", link.healthy ? "#22c55e" : "#ef4444");
    line.setAttribute("stroke-width", "2");
    line.setAttribute("marker-end", "url(#arrow)");
    svg.appendChild(line);
  }

  // Draw nodes.
  for (const node of nodes) {
    const g = document.createElementNS(ns, "g");
    const circle = document.createElementNS(ns, "circle");
    circle.setAttribute("cx", String(node.x ?? 0));
    circle.setAttribute("cy", String(node.y ?? 0));
    circle.setAttribute("r", "12");
    circle.setAttribute("fill", "#3b82f6");
    circle.setAttribute("stroke", "#1e40af");
    circle.setAttribute("stroke-width", "2");
    g.appendChild(circle);

    const text = document.createElementNS(ns, "text");
    text.setAttribute("x", String(node.x ?? 0));
    text.setAttribute("y", String((node.y ?? 0) + 26));
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("font-size", "11");
    text.setAttribute("fill", "#374151");
    text.textContent = node.label;
    g.appendChild(text);
    svg.appendChild(g);
  }
}
