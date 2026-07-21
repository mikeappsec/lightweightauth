import { type JSX, onCleanup, onMount } from "solid-js";

// Scroll-triggered fade-up reveal. Starts hidden/offset (`.reveal-init` in
// index.css) and flips to `.reveal-visible` the first time the element
// crosses the viewport, via IntersectionObserver — then disconnects, so
// this never re-triggers on scroll-back (a one-shot entrance, not a
// repeating scroll gimmick). `prefers-reduced-motion` is handled globally
// in index.css (the transition itself collapses to ~0), so no separate
// branch is needed here.
export function Reveal(props: {
  children: JSX.Element;
  /** Stagger index for list children — 40ms per step, per standard
   * stagger-entrance guidance (30-50ms/item). */
  index?: number;
  class?: string;
}) {
  let ref: HTMLDivElement | undefined;

  onMount(() => {
    if (!ref) return;
    if (typeof IntersectionObserver === "undefined") {
      // Test environments (jsdom/happy-dom) and any browser without
      // IntersectionObserver support: skip straight to visible instead
      // of throwing.
      ref.classList.remove("reveal-init");
      ref.classList.add("reveal-visible");
      return;
    }
    const delay = (props.index ?? 0) * 40;
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const el = entry.target as HTMLElement;
            el.style.transitionDelay = `${delay}ms`;
            el.classList.remove("reveal-init");
            el.classList.add("reveal-visible");
            observer.unobserve(el);
          }
        }
      },
      { threshold: 0.1, rootMargin: "0px 0px -40px 0px" },
    );
    observer.observe(ref);
    onCleanup(() => observer.disconnect());
  });

  return (
    <div ref={ref} class={`reveal-init ${props.class ?? ""}`}>
      {props.children}
    </div>
  );
}
