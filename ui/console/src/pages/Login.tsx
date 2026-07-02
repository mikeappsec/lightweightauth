import { createSignal, Show } from "solid-js";
import { ShieldCheck, LogIn } from "lucide-solid";
import { login, type SessionInfo } from "../api/client";

export default function Login(props: { onSuccess: (s: SessionInfo) => void }) {
  const [username, setUsername] = createSignal("admin");
  const [password, setPassword] = createSignal("");
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
    <div class="min-h-screen flex items-center justify-center bg-gray-950 px-4">
      <div class="w-full max-w-sm">
        <div class="flex flex-col items-center mb-8">
          <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center mb-3">
            <ShieldCheck size={26} class="text-white" />
          </div>
          <h1 class="text-white font-semibold text-lg tracking-tight">LightweightAuth</h1>
          <p class="text-xs text-gray-500 mt-0.5">Control Plane Console</p>
        </div>

        <form
          onSubmit={submit}
          class="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-4 shadow-xl"
        >
          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1.5">Username</label>
            <input
              type="text"
              autocomplete="username"
              value={username()}
              onInput={(e) => setUsername(e.currentTarget.value)}
              class="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600/50 focus:border-blue-600"
            />
          </div>

          <div>
            <label class="block text-xs font-medium text-gray-400 mb-1.5">Password</label>
            <input
              type="password"
              autocomplete="current-password"
              value={password()}
              onInput={(e) => setPassword(e.currentTarget.value)}
              class="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-gray-100 text-sm focus:outline-none focus:ring-2 focus:ring-blue-600/50 focus:border-blue-600"
            />
          </div>

          <Show when={error()}>
            <p class="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              {error()}
            </p>
          </Show>

          <button
            type="submit"
            disabled={busy() || !password()}
            class="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
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
