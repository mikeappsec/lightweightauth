// Minimal line-based YAML/JSON tokenizer for the console's config
// previews (wizard-generated auth config + Helm values, and the
// pushed instance config). Deliberately not a full parser — the
// content here is always machine-generated (provisioner output) or
// backend-validated JSON, never arbitrary free-form YAML with
// anchors/multiline block scalars, so a per-line regex pass covers it
// without pulling in a full grammar (Shiki/Prism) for two languages.
//
// Secret handling: /v1/controlplane/instances/{cluster}/{name}/config*
// responses (GET, the POST-push echo, /config/history, /config/rollback)
// are now redacted server-side (internal/controlplane/configmgmt/redact.go)
// with structural knowledge this regex can't have — e.g. apikey's
// `static` mode stores raw API keys as map KEYS, which no key-name
// pattern can ever catch. The masking here is now defense-in-depth /
// preview-path coverage only, for: the create-instance wizard's preview
// (deliberately left unredacted server-side — it's the same user's own
// just-typed input in the same session, never persisted), and as a second
// independent check against a gap in the server's rule table. It cannot
// catch a secret-as-map-key pattern; only the server-side redaction does.
// Don't "fix" this regex chasing a case that's actually solved server-side
// — check redact.go's moduleRules first.

export type TokenKind =
  | "key"
  | "string"
  | "number"
  | "boolean"
  | "comment"
  | "punctuation"
  | "secret"
  | "plain";

export interface Token {
  text: string;
  kind: TokenKind;
}

export type CodeLanguage = "yaml" | "json";

// Key names whose inline scalar value gets classified as "secret".
// Deliberately narrow: caBundle/cert/trustedCAs are public material an
// operator needs to actually read to verify, so they're excluded. Keep
// in sync with the Go-side heuristicSecretKeyRE in redact.go (used for
// module types with no explicit rule table entry) — the two exist to
// catch each other's gaps, so drift between them quietly reopens one.
const SECRET_KEY_RE =
  /\b(secret|password|passphrase|token|api[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret|credential|hash)\b/i;

function isSecretKey(key: string): boolean {
  return SECRET_KEY_RE.test(key.trim());
}

export function highlight(code: string, language: CodeLanguage): Token[][] {
  const lines = code.split("\n");
  return lines.map((line) => (language === "yaml" ? tokenizeYamlLine(line) : tokenizeJsonLine(line)));
}

export function containsSecrets(code: string, language: CodeLanguage): boolean {
  return highlight(code, language).some((line) => line.some((t) => t.kind === "secret"));
}

// ── YAML ─────────────────────────────────────────────────────────────

function tokenizeYamlLine(line: string): Token[] {
  const tokens: Token[] = [];

  const commentIdx = findUnquotedHash(line);
  const codePart = commentIdx === -1 ? line : line.slice(0, commentIdx);
  const commentPart = commentIdx === -1 ? "" : line.slice(commentIdx);

  // Leading indentation + any "- " list-item markers.
  const leadMatch = codePart.match(/^(\s*(?:-\s+)*)/);
  const lead = leadMatch ? leadMatch[0] : "";
  const rest = codePart.slice(lead.length);
  if (lead) tokens.push({ text: lead, kind: "plain" });

  // "^([^:]+?)(:)" also matches the scheme separator of a bare scalar
  // list item like "- https://example.com" (rawKey would capture just
  // "https") — those are never real YAML mapping keys in this app's
  // generated config, so exclude the schemes it actually emits
  // (jwksUrl/grpc endpoints, SPIFFE IDs, vault:// secret references).
  const kvMatch = rest.match(/^([^:]+?)(:)(\s*)(.*)$/);
  const isSchemeColon = kvMatch !== null && /^(https?|wss?|grpcs?|spiffe|vault|unix)$/i.test(kvMatch[1].trim());
  if (kvMatch && !isSchemeColon) {
    const [, rawKey, colon, gap, rawValue] = kvMatch;
    tokens.push({ text: rawKey, kind: "key" });
    tokens.push({ text: colon, kind: "punctuation" });
    if (gap) tokens.push({ text: gap, kind: "plain" });
    if (rawValue) {
      tokens.push(...tokenizeYamlScalar(rawValue, isSecretKey(rawKey)));
    }
  } else if (rest) {
    tokens.push(...tokenizeYamlScalar(rest, false));
  }

  if (commentPart) tokens.push({ text: commentPart, kind: "comment" });
  return tokens;
}

function tokenizeYamlScalar(text: string, isSecret: boolean): Token[] {
  const trimmed = text.trim();
  if (!trimmed) return [{ text, kind: "plain" }];
  if (isSecret) return [{ text, kind: "secret" }];
  if (/^"([^"\\]|\\.)*"$/.test(trimmed) || /^'([^']|'')*'$/.test(trimmed)) {
    return [{ text, kind: "string" }];
  }
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    return [{ text, kind: "number" }];
  }
  if (/^(true|false|null|~)$/i.test(trimmed)) {
    return [{ text, kind: "boolean" }];
  }
  return [{ text, kind: "string" }];
}

function findUnquotedHash(line: string): number {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === "'" && !inDouble) inSingle = !inSingle;
    else if (c === '"' && !inSingle) inDouble = !inDouble;
    else if (c === "#" && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return i;
    }
  }
  return -1;
}

// ── JSON ─────────────────────────────────────────────────────────────

const JSON_TOKEN_RE =
  /(\s+)|("(?:[^"\\]|\\.)*")(\s*:)?|([{}[\],])|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(true|false|null)/g;

function tokenizeJsonLine(line: string): Token[] {
  const tokens: Token[] = [];
  let pendingKey: string | null = null;
  JSON_TOKEN_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = JSON_TOKEN_RE.exec(line)) !== null) {
    const [, ws, str, colonAfterStr, punct, num, lit] = match;
    if (ws !== undefined) {
      tokens.push({ text: ws, kind: "plain" });
      continue;
    }
    if (str !== undefined) {
      if (colonAfterStr) {
        tokens.push({ text: str, kind: "key" });
        tokens.push({ text: colonAfterStr, kind: "punctuation" });
        pendingKey = str.slice(1, -1);
      } else {
        const secret = pendingKey !== null && isSecretKey(pendingKey);
        tokens.push({ text: str, kind: secret ? "secret" : "string" });
        pendingKey = null;
      }
      continue;
    }
    if (punct !== undefined) {
      tokens.push({ text: punct, kind: "punctuation" });
      continue;
    }
    if (num !== undefined) {
      tokens.push({ text: num, kind: "number" });
      continue;
    }
    if (lit !== undefined) {
      tokens.push({ text: lit, kind: "boolean" });
      continue;
    }
  }
  return tokens;
}
