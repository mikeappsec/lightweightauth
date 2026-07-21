/* @refresh reload */
import { render } from "solid-js/web";
import { Router, Route } from "@solidjs/router";
import { QueryClient, QueryClientProvider } from "@tanstack/solid-query";
import { lazy } from "solid-js";
import App from "./App";
import AuthGate from "./auth/AuthGate";
import "./index.css";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Instances = lazy(() => import("./pages/Instances"));
const InstanceDetail = lazy(() => import("./pages/InstanceDetail"));
const CreateInstanceWizard = lazy(() => import("./pages/CreateInstanceWizard"));
const Clusters = lazy(() => import("./pages/Clusters"));
const ConfigEditor = lazy(() => import("./pages/ConfigEditor"));
const Routes = lazy(() => import("./pages/Routes"));
const MeshGraph = lazy(() => import("./pages/MeshGraph"));
const Decisions = lazy(() => import("./pages/Decisions"));
const Alerts = lazy(() => import("./pages/Alerts"));
const PolicyAnalytics = lazy(() => import("./pages/PolicyAnalytics"));
const PolicyExplain = lazy(() => import("./pages/PolicyExplain"));
const Health = lazy(() => import("./pages/Health"));

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
      <AuthGate>
        <Router root={App}>
          <Route path="/" component={Dashboard} />
          <Route path="/instances" component={Instances} />
          <Route path="/instances/:cluster/:name" component={InstanceDetail} />
          <Route path="/instances/:cluster/:name/config" component={ConfigEditor} />
          <Route path="/clusters" component={Clusters} />
          <Route path="/routes" component={Routes} />
          <Route path="/mesh" component={MeshGraph} />
          <Route path="/decisions" component={Decisions} />
          <Route path="/alerts" component={Alerts} />
          <Route path="/policies" component={PolicyAnalytics} />
          <Route path="/policies/explain" component={PolicyExplain} />
          <Route path="/health" component={Health} />
        </Router>
      </AuthGate>
    </QueryClientProvider>
  ),
  root,
);
