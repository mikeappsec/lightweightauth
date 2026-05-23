import { type ParentProps } from "solid-js";
import { A } from "@solidjs/router";

export default function App(props: ParentProps) {
  return (
    <div class="min-h-screen flex">
      {/* Sidebar */}
      <nav class="w-56 bg-gray-900 text-gray-100 flex flex-col p-4 gap-1">
        <h1 class="text-lg font-bold mb-6 px-2">lwauth</h1>
        <NavLink href="/" label="Dashboard" />
        <NavLink href="/instances" label="Instances" />
        <NavLink href="/clusters" label="Clusters" />
        <NavLink href="/routes" label="Routes" />
        <NavLink href="/mesh" label="Mesh" />
        <NavLink href="/decisions" label="Decisions" />
        <NavLink href="/health" label="Health" />
      </nav>

      {/* Main content */}
      <main class="flex-1 p-6 overflow-auto">
        {props.children}
      </main>
    </div>
  );
}

function NavLink(props: { href: string; label: string }) {
  return (
    <A
      href={props.href}
      class="px-3 py-2 rounded text-sm hover:bg-gray-800 transition-colors"
      activeClass="bg-gray-800 font-medium"
    >
      {props.label}
    </A>
  );
}

