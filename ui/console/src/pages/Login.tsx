import { createSignal, Show } from "solid-js";
import { ShieldCheck, LogIn, Eye, EyeOff } from "lucide-solid";
import { login, type SessionInfo } from "../api/client";
import { AmbientBackground } from "../components/AmbientBackground";

export default function Login(props: { onSuccess: (s: SessionInfo) => void }) {
  const [username, setUsername] = createSignal("admin");
  const [password, setPassword] = createSignal("");
  const [showPassword, setShowPassword] = createSignal(false);
  const [error, setError] = createSignal("");
  const [busy, setBusy] = createSignal(false);

  const submit = async (e: Event) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const session = await login(username(), password());
      props.onSuccess(session);
    } catch {
      setError("Invalid username or password.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="relative min-h-screen flex items-center justify-center bg-void px-4 overflow-hidden">
      {/* The login screen deliberately always renders in the dark
          "brand" palette (matching the sidebar) regardless of the
          console's light/dark preference — it's shown before the
          operator has a session, so there's no saved preference to
          honor yet, and a consistent unauthenticated screen avoids a
          jarring theme flash right before the themed console mounts. */}
      <AmbientBackground />

      <div class="relative w-full max-w-sm animate-fade-up">
        <div class="flex flex-col items-center mb-8">
          <div class="relative w-14 h-14 rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center mb-4 shadow-[0_0_40px_-8px_rgba(99,102,241,0.6)]">
            <ShieldCheck size={28} class="text-white" />
          </div>
          <h1 class="font-display text-white font-semibold text-xl tracking-tight">LightweightAuth</h1>
          <p class="text-xs text-gray-500 mt-1 tracking-wide uppercase">Control Plane Console</p>
        </div>

        <form
          onSubmit={submit}
          class="glass-panel rounded-2xl p-6 space-y-4 shadow-2xl animate-scale-in"
          style={{ "animation-delay": "80ms" }}
        >
          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1.5" for="login-username">
              Username
            </label>
            <input
              id="login-username"
              type="text"
              autocomplete="username"
              value={username()}
              onInput={(e) => setUsername(e.currentTarget.value)}
              class="w-full px-3 py-2.5 rounded-lg bg-black/30 border border-white/10 text-gray-100 text-sm outline-none transition-all focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500"
            />
          </div>

          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1.5" for="login-password">
              Password
            </label>
            <div class="relative">
              <input
                id="login-password"
                type={showPassword() ? "text" : "password"}
                autocomplete="current-password"
                value={password()}
                onInput={(e) => setPassword(e.currentTarget.value)}
                class="w-full px-3 py-2.5 pr-10 rounded-lg bg-black/30 border border-white/10 text-gray-100 text-sm outline-none transition-all focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                class="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                aria-label={showPassword() ? "Hide password" : "Show password"}
                tabIndex={-1}
              >
                {showPassword() ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <Show when={error()}>
            <p class="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 animate-fade-up" role="alert">
              {error()}
            </p>
          </Show>

          <button
            type="submit"
            disabled={busy() || !password()}
            class="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-all shadow-[0_0_24px_-6px_rgba(99,102,241,0.6)] disabled:shadow-none"
          >
            <LogIn size={16} />
            {busy() ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p class="text-center text-[10px] text-gray-600 mt-6">
          Authorized administrators only.
        </p>
      </div>
    </div>
  );
}
