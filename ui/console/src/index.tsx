/* @refresh reload */
import { render } from "solid-js/web";
import { Router } from "@solidjs/router";
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import App from "./App";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 10_000,
    },
  },
});

const root = document.getElementById("root");
if (!root) throw new Error("Root element not found");

render(
  () => (
    <QueryClientProvider client={queryClient}>
      <Router root={App}>
        {/* Routes are defined in App.tsx via lazy imports */}
      </Router>
    </QueryClientProvider>
  ),
  root,
);
