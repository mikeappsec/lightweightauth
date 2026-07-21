// Consistent pulsing-glow status dot — replaces the ad-hoc "Connected"
// pill, the Decisions Radio icon, and Alerts' connection pill with one
// shared treatment. `live` uses --color-live (cyan) so "happening right
// now" reads distinctly from ordinary status colors; other tones reuse
// the app's existing semantic colors so it doesn't invent a second
// meaning for red/green/amber.
const TONE_CLASS: Record<Tone, string> = {
  live: "bg-cyan-400 shadow-[0_0_0_0_rgba(34,211,238,0.5)]",
  healthy: "bg-emerald-400 shadow-[0_0_0_0_rgba(52,211,153,0.5)]",
  critical: "bg-red-400 shadow-[0_0_0_0_rgba(248,113,113,0.5)]",
  idle: "bg-gray-400 dark:bg-gray-600",
};

type Tone = "live" | "healthy" | "critical" | "idle";

export function GlowDot(props: { tone: Tone; pulse?: boolean; class?: string; label?: string }) {
  return (
    <span
      class={`inline-flex items-center gap-1.5 ${props.class ?? ""}`}
      role={props.label ? "status" : undefined}
      aria-label={props.label}
    >
      <span
        class={`relative inline-flex h-2 w-2 rounded-full ${TONE_CLASS[props.tone]} ${
          props.pulse !== false && props.tone !== "idle" ? "animate-glow-pulse" : ""
        }`}
      />
      {props.label && <span class="text-xs text-gray-500 dark:text-gray-400">{props.label}</span>}
    </span>
  );
}
