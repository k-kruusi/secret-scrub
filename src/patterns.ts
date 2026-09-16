/**
 * Pattern battery for secrets redaction.
 *
 * Order matters: more-specific prefix patterns (Anthropic, OpenAI, GitHub, …)
 * are listed before the generic fallbacks (bearer, credential assignment, URL
 * params) so a sk-ant-… key isn't also partially caught by the sk- pattern.
 *
 * Replacement tokens use [REDACTED:<kind>] — the brackets are deliberately
 * excluded from every value char-class so a second scrub pass never
 * re-matches a token we already emitted (structural idempotency).
 */

export type Kind =
  | "anthropic-key"
  | "openai-key"
  | "xai-key"
  | "github-token"
  | "github-pat"
  | "gitlab-pat"
  | "slack-token"
  | "google-api-key"
  | "aws-key"
  | "pem-block"
  | "jwt"
  | "bearer"
  | "credential"
  | "url-secret";

export interface Hit {
  kind: string;
  count: number;
}

export interface PatternEntry {
  kind: Kind;
  /** Always global. Reset lastIndex before use. */
  re: RegExp;
  /**
   * Called with (fullMatch, ...captureGroups) — return the replacement string.
   * Return `match` unchanged to signal "this hit is benign, don't count it."
   * Omit to replace the full match with `[REDACTED:<kind>]`.
   */
  replace?: (match: string, ...groups: string[]) => string;
}

const R = (kind: Kind): string => `[REDACTED:${kind}]`;

/**
 * Return true if a captured value is clearly NOT a secret:
 *   - git SHAs / cryptographic hashes (pure hex, 7-128 chars)
 *   - UUIDs
 *   - npm integrity hashes (sha256-… / sha512-…)
 *   - cite.mjs receipt tokens (contain @hex#hex suffix)
 *   - boolean / null literals
 *   - all-alpha strings (English words, no digits or specials)
 *   - short (< 16 char) purely base64-alphabet strings (version numbers, IDs)
 */
function isBenignValue(value: string): boolean {
  if (!value) return true;

  // Boolean / null-like literals
  if (/^(?:true|false|null|undefined|none|empty|yes|no)$/i.test(value)) return true;

  // Pure hex — git SHAs (7-40 chars), SHA-256 (64), SHA-512 (128), BLAKE3 (64)
  if (/^[0-9a-fA-F]+$/.test(value) && value.length >= 7 && value.length <= 128) return true;

  // UUID (with dashes)
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true;

  // npm integrity hash: sha256-<base64> or sha512-<base64>
  if (/^sha(?:256|512)-[a-zA-Z0-9+/]+=*$/.test(value)) return true;

  // cite.mjs receipt token: …@<commit7+>#<hash8+>  (format: <path>:L<n>-L<m>@<sha7>#<hash8>)
  if (/@[0-9a-f]{7,40}#[0-9a-f]{8,}$/.test(value)) return true;

  // All-alphabetic — English words / identifiers unlikely to be secrets
  if (/^[a-zA-Z]+$/.test(value)) return true;

  // Short (< 16 chars) purely base64-alphabet — version numbers, short IDs
  if (value.length < 16 && /^[a-zA-Z0-9+/=]+$/.test(value)) return true;

  return false;
}

/**
 * The ordered pattern list. Sequential application — each pass operates on
 * the output of the previous — is safe because:
 *   a) Specific-prefix patterns run first, leaving [REDACTED:…] tokens.
 *   b) [ and ] are excluded from every value char-class in later patterns,
 *      so those tokens are never re-matched.
 */
export const PATTERNS: PatternEntry[] = [
  // ── Vendor-prefixed API keys (most reliable — false-positive rate near zero) ──

  {
    kind: "anthropic-key",
    // sk-ant-… (listed before generic sk- to prevent double-hit)
    re: /sk-ant-[a-zA-Z0-9\-_]{20,}/g,
  },
  {
    kind: "openai-key",
    // sk- or sk_ (OpenAI, Mistral, and similar services)
    re: /sk[-_][a-zA-Z0-9\-_]{20,}/g,
  },
  {
    kind: "xai-key",
    re: /xai-[a-zA-Z0-9]{20,}/g,
  },
  {
    kind: "github-token",
    // ghp_ PAT classic, gho_ OAuth, ghu_ user-to-server, ghs_ server-to-server, ghr_ refresh
    re: /gh[pousr]_[a-zA-Z0-9]{36,}/g,
  },
  {
    kind: "github-pat",
    // Fine-grained PAT (github_pat_…)
    re: /github_pat_[a-zA-Z0-9_]{36,}/g,
  },
  {
    kind: "gitlab-pat",
    re: /glpat-[a-zA-Z0-9\-_]{20,}/g,
  },
  {
    kind: "slack-token",
    // xoxa- workspace, xoxb- bot, xoxp- user, xapp- app-level
    re: /(?:xox[abp]|xapp)-[a-zA-Z0-9\-]{20,}/g,
  },
  {
    kind: "google-api-key",
    // AIza + exactly 35 chars = 39-char total
    re: /AIza[a-zA-Z0-9\-_]{35}/g,
  },
  {
    kind: "aws-key",
    // AKIA (long-term) or ASIA (temporary/STS) + 16 uppercase alphanumeric
    re: /(?:AKIA|ASIA)[A-Z0-9]{16}/g,
  },

  // ── PEM private key blocks (multiline — must be applied before JWT so the
  //    base64 body inside a PEM isn't partially caught by the JWT pattern) ──
  {
    kind: "pem-block",
    re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g,
  },

  // ── Bearer token in Authorization header ──
  // Listed BEFORE jwt: when a JWT appears as a bearer value, the more specific
  // context (bearer auth) is the semantically meaningful label.
  {
    kind: "bearer",
    // Keeps "Authorization: Bearer " prefix; replaces only the token value.
    // Value class includes '.' so JWT-shaped bearer tokens are caught here
    // before the jwt pattern can fire on them.
    // [ ] excluded so [REDACTED:…] already in place won't re-match.
    re: /(Authorization\s*:\s*Bearer\s+)[a-zA-Z0-9\-_.~+/=]{16,}/gi,
    replace: (_match: string, prefix: string): string => `${prefix}${R("bearer")}`,
  },

  // ── Bare JWTs (eyJ is base64 of '{"' — very low false-positive rate) ──
  // Runs AFTER bearer so a JWT in an Authorization header is labelled "bearer".
  {
    kind: "jwt",
    // Three base64url segments, ≥ 4 chars each; the eyJ prefix gates the header.
    re: /eyJ[a-zA-Z0-9_\-]{4,}\.[a-zA-Z0-9_\-]{4,}\.[a-zA-Z0-9_\-]{4,}/g,
  },

  // ── Sensitive URL query parameters — keep key name, redact value only ──
  // Listed BEFORE the generic credential pattern so URL params like
  // `?access_token=…` preserve their key name instead of being fully replaced.
  {
    kind: "url-secret",
    // [ ] excluded from value class — [REDACTED:…] already in place won't re-match.
    re: /([?&](?:access_token|api_key|token|key|secret|password)=)([^\s&"'#<>[\]]{8,})/gi,
    replace: (_match: string, keyPart: string): string => `${keyPart}${R("url-secret")}`,
  },

  // ── Credential assignment forms: keyword = "secret-value" ──
  {
    kind: "credential",
    // Word-boundary lookbehind/lookahead blocks substring matches:
    //   sessionToken=… won't fire (word char before keyword)
    //   secret_key=… won't fire (word char after keyword)
    // Value class: broad but excludes whitespace, quotes, structural chars, and
    // [ ] to prevent re-matching [REDACTED:…] tokens from earlier passes.
    re: /(?<![a-zA-Z0-9_])(?:api_key|apikey|access_token|refresh_token|id_token|client_secret|secret|password|token)(?![a-zA-Z0-9_])\s*[:=]\s*["']?([^\s"',;[\]<>]{8,})["']?/gi,
    replace: (match: string, value: string): string => {
      if (isBenignValue(value)) return match;
      return R("credential");
    },
  },
];
