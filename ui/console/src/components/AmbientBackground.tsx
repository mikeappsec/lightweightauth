// Drifting gradient-blob backdrop for "hero" moments (Login, Dashboard,
// Health). Pure CSS (`animate-gradient-drift`, defined in index.css) —
// no JS, no canvas. Under prefers-reduced-motion the global media query
// collapses the animation duration to ~0, which freezes the blobs in
// place rather than making them vanish — the ambient depth stays, only
// the motion stops.
//
// Absolutely positioned within a `relative` ancestor; render this first
// so page content stacks on top via normal document order.
export function AmbientBackground() {
  return (
    <div class="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
      <div
        class="animate-gradient-drift absolute -top-32 -left-20 h-96 w-96 rounded-full opacity-30 dark:opacity-40 blur-3xl"
        style={{ background: "radial-gradient(circle, #6366f1, transparent 70%)" }}
      />
      <div
        class="animate-gradient-drift absolute top-1/3 -right-24 h-[28rem] w-[28rem] rounded-full opacity-20 dark:opacity-30 blur-3xl"
        style={{ background: "radial-gradient(circle, #22d3ee, transparent 70%)", "animation-delay": "-6s" }}
      />
      <div
        class="animate-gradient-drift absolute -bottom-40 left-1/4 h-80 w-80 rounded-full opacity-20 dark:opacity-25 blur-3xl"
        style={{ background: "radial-gradient(circle, #818cf8, transparent 70%)", "animation-delay": "-11s" }}
      />
    </div>
  );
}
