import { createEffect, createSignal, onCleanup } from "solid-js";

const easeOutExpo = (t: number) => (t === 1 ? 1 : 1 - Math.pow(2, -10 * t));

// Ticks a KPI number up from its previous value to `props.value` over
// ~700ms using requestAnimationFrame + an expo-out ease — no animation
// library needed for a single-property numeric tween. Re-triggers
// whenever `value` changes (e.g. a live metrics refresh), always
// animating from the number currently on screen, not from zero.
export function AnimatedNumber(props: { value: number; format?: (n: number) => string }) {
  const [display, setDisplay] = createSignal(props.value);
  let raf: number | undefined;
  let from = props.value;

  createEffect(() => {
    const to = props.value;

    // Reduced-motion: the global CSS media query only covers
    // transitions/CSS animations, not this rAF-driven tween — jump
    // straight to the target value instead.
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      setDisplay(to);
      from = to;
      return;
    }

    const start = performance.now();
    const startValue = from;
    const duration = 700;

    if (raf) cancelAnimationFrame(raf);
    const step = (now: number) => {
      const elapsed = now - start;
      const t = Math.min(1, elapsed / duration);
      setDisplay(Math.round(startValue + (to - startValue) * easeOutExpo(t)));
      if (t < 1) {
        raf = requestAnimationFrame(step);
      } else {
        from = to;
      }
    };
    raf = requestAnimationFrame(step);
  });

  onCleanup(() => {
    if (raf) cancelAnimationFrame(raf);
  });

  return <>{props.format ? props.format(display()) : display().toLocaleString()}</>;
}
