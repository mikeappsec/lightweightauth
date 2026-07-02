import { createSignal } from "solid-js";
import type { SessionInfo } from "../api/client";

// Global console session state, shared between the auth gate and the layout.
export const [session, setSession] = createSignal<SessionInfo | null>(null);
