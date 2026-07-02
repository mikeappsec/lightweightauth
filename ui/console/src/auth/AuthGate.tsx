import { onMount, onCleanup, Show, type JSX } from "solid-js";
import { getSession } from "../api/client";
import { session, setSession } from "./store";
import Login from "../pages/Login";

// AuthGate probes the login state on load and renders either the login screen
// or the console. When login is disabled on the server (developer mode) the
// session probe reports authenticated=true, so the console renders directly.
export default function AuthGate(props: { children: JSX.Element }) {
  const onUnauthenticated = () =>
    setSession((prev) => (prev ? { ...prev, authenticated: false } : prev));

  onMount(async () => {
    try {
      setSession(await getSession());
    } catch {
      setSession({ authenticated: false, user: "", authEnabled: true });
    }
    window.addEventListener("lwauth:unauthenticated", onUnauthenticated);
  });

  onCleanup(() => window.removeEventListener("lwauth:unauthenticated", onUnauthenticated));

  return (
    <Show
      when={session() !== null}
      fallback={
        <div class="min-h-screen flex items-center justify-center bg-gray-950 text-gray-500 text-sm">
          Loading…
        </div>
      }
    >
      <Show
        when={session()?.authenticated}
        fallback={<Login onSuccess={(s) => setSession(s)} />}
      >
        {props.children}
      </Show>
    </Show>
  );
}
