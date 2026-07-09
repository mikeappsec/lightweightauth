import { type ParentProps, type JSX, Show } from "solid-js";
import { A, useLocation } from "@solidjs/router";
import {
  LayoutDashboard,
  Server,
  Globe,
  Route,
  Network,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Settings,
  LogOut,
} from "lucide-solid";
import { logout } from "./api/client";
import { session, setSession } from "./auth/store";

export default function App(props: ParentProps) {
  const handleLogout = async () => {
    try {
      await logout();
    } catch {
      /* ignore — clear local state regardless */
    }
    setSession({ authenticated: false, user: "", authEnabled: true });
  };

  return (
    <div class="min-h-screen flex bg-gray-50">
      {/* Sidebar */}
      <aside class="w-64 bg-gray-950 text-gray-300 flex flex-col border-r border-gray-800 shrink-0">
        {/* Brand */}
        <div class="h-16 flex items-center gap-3 px-5 border-b border-gray-800">
          <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center">
            <ShieldCheck size={18} class="text-white" />
          </div>
          <div>
            <span class="text-white font-semibold text-sm tracking-tight">LightweightAuth</span>
            <span class="block text-[10px] text-gray-500 -mt-0.5">Control Plane</span>
          </div>
        </div>

        {/* Navigation */}
        <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <NavSection label="Overview">
            <NavLink href="/" icon={LayoutDashboard} label="Dashboard" />
          </NavSection>

          <NavSection label="Infrastructure">
            <NavLink href="/instances" icon={Server} label="Instances" />
            <NavLink href="/clusters" icon={Globe} label="Clusters" />
            <NavLink href="/routes" icon={Route} label="Routes" />
            <NavLink href="/mesh" icon={Network} label="Service Mesh" />
          </NavSection>

          <NavSection label="Observability">
            <NavLink href="/decisions" icon={ShieldCheck} label="Decisions" />
            <NavLink href="/alerts" icon={AlertTriangle} label="Alerts" />
            <NavLink href="/health" icon={Activity} label="Health" />
          </NavSection>
        </nav>

        {/* Footer */}
        <div class="border-t border-gray-800 px-4 py-3 space-y-2">
          <Show when={session()?.authEnabled}>
            <div class="flex items-center gap-2 text-xs">
              <div class="w-6 h-6 rounded-full bg-blue-600/20 text-blue-300 flex items-center justify-center text-[10px] font-semibold uppercase">
                {(session()?.user ?? "?").slice(0, 1)}
              </div>
              <span class="text-gray-300 truncate">{session()?.user}</span>
              <button
                onClick={handleLogout}
                title="Sign out"
                class="ml-auto flex items-center gap-1 text-gray-500 hover:text-red-400 transition-colors"
              >
                <LogOut size={14} />
              </button>
            </div>
          </Show>
          <div class="flex items-center gap-2 text-xs text-gray-500">
            <Settings size={14} />
            <span>v1.2.0</span>
            <span class="ml-auto px-1.5 py-0.5 bg-green-500/10 text-green-400 rounded text-[10px] font-medium">
              Connected
            </span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div class="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header class="h-16 bg-white border-b border-gray-200 flex items-center px-6 shrink-0">
          <Breadcrumb />
        </header>

        {/* Page content */}
        <main class="flex-1 p-6 overflow-auto">
          {props.children}
        </main>
      </div>
    </div>
  );
}

function NavSection(props: { label: string; children: JSX.Element }) {
  return (
    <div class="mb-4">
      <p class="px-3 mb-1 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
        {props.label}
      </p>
      {props.children}
    </div>
  );
}

function NavLink(props: { href: string; icon: (p: any) => JSX.Element; label: string }) {
  const location = useLocation();
  const isActive = () => {
    if (props.href === "/") return location.pathname === "/";
    return location.pathname.startsWith(props.href);
  };

  return (
    <A
      href={props.href}
      class={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-150 ${
        isActive()
          ? "bg-blue-600/10 text-blue-400 font-medium"
          : "hover:bg-gray-800/60 hover:text-gray-100"
      }`}
    >
      <props.icon size={18} class={isActive() ? "text-blue-400" : "text-gray-500"} />
      {props.label}
    </A>
  );
}

function Breadcrumb() {
  const location = useLocation();
  const parts = () => location.pathname.split("/").filter(Boolean);

  return (
    <div class="flex items-center gap-1.5 text-sm">
      <A href="/" class="text-gray-500 hover:text-gray-900">Home</A>
      {parts().map((part, i) => (
        <>
          <span class="text-gray-300">/</span>
          <span class={i === parts().length - 1 ? "text-gray-900 font-medium capitalize" : "text-gray-500 capitalize"}>
            {decodeURIComponent(part)}
          </span>
        </>
      ))}
    </div>
  );
}

