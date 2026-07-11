import { describe, expect, it } from "vitest";
import { highlight, containsSecrets } from "./highlight";

function kinds(line: ReturnType<typeof highlight>[number]) {
  return line.map((t) => t.kind);
}

describe("highlight (yaml)", () => {
  it("tokenizes a simple key/value pair", () => {
    const [line] = highlight("name: payments-auth", "yaml");
    expect(kinds(line)).toEqual(["key", "punctuation", "plain", "string"]);
    expect(line.find((t) => t.kind === "string")?.text).toBe("payments-auth");
  });

  it("tokenizes list items and nested indentation", () => {
    const lines = highlight("identifiers:\n  - name: jwt-1\n    type: jwt", "yaml");
    expect(kinds(lines[0])).toEqual(["key", "punctuation"]);
    expect(lines[1][0].kind).toBe("plain"); // leading "  - " marker
    expect(lines[1].some((t) => t.kind === "key" && t.text === "name")).toBe(true);
  });

  it("does not mistake a URL scheme colon for a mapping key", () => {
    const [line] = highlight("    jwksUrl: https://auth.example.com/.well-known/jwks.json", "yaml");
    const keyToken = line.find((t) => t.kind === "key");
    expect(keyToken?.text).toBe("jwksUrl");
    // The scheme separator inside the value must not itself be parsed as another key.
    expect(line.filter((t) => t.kind === "key")).toHaveLength(1);
  });

  it("classifies numbers, booleans, and comments", () => {
    const [line] = highlight("rps: 100 # requests per second", "yaml");
    expect(line.some((t) => t.kind === "number" && t.text.trim() === "100")).toBe(true);
    expect(line.some((t) => t.kind === "comment")).toBe(true);
    // Tokens must reconstruct the exact original line — no characters
    // dropped or reordered by the split between value and comment.
    expect(line.map((t) => t.text).join("")).toBe("rps: 100 # requests per second");
  });

  it("redacts secret-shaped keys but not public material", () => {
    const [secretLine] = highlight("signingKey: vault://kv/lwauth/signing-key", "yaml");
    expect(secretLine.some((t) => t.kind === "secret")).toBe(true);

    const [publicLine] = highlight("trustedCAs: /etc/lwauth/ca-bundle.pem", "yaml");
    expect(publicLine.some((t) => t.kind === "secret")).toBe(false);
  });
});

describe("highlight (json)", () => {
  it("tokenizes keys, strings, numbers, and booleans", () => {
    const [line] = highlight('{"name": "payments-auth", "replicas": 2, "enabled": true}', "json");
    expect(line.filter((t) => t.kind === "key").map((t) => t.text)).toEqual(
      expect.arrayContaining(['"name"', '"replicas"', '"enabled"']),
    );
    expect(line.some((t) => t.kind === "number" && t.text === "2")).toBe(true);
    expect(line.some((t) => t.kind === "boolean" && t.text === "true")).toBe(true);
  });

  it("redacts values for secret-shaped keys", () => {
    const [line] = highlight('{"clientSecret": "sk_live_abc123"}', "json");
    expect(line.some((t) => t.kind === "secret" && t.text === '"sk_live_abc123"')).toBe(true);
  });
});

describe("containsSecrets", () => {
  it("is true only when a secret-shaped key has an inline value", () => {
    expect(containsSecrets("password: hunter2", "yaml")).toBe(true);
    expect(containsSecrets("username: alice", "yaml")).toBe(false);
    expect(containsSecrets('{"apiKey": "abc"}', "json")).toBe(true);
    expect(containsSecrets('{"username": "alice"}', "json")).toBe(false);
  });
});
