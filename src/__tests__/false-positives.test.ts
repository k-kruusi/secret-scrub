/**
 * Live Proof 2: corpus of real repo text that MUST survive scrubbing unchanged.
 *
 * Includes:
 *   - ≥5 cite.mjs-format receipt tokens (path:L1-L5@commit#hash)
 *   - ≥5 git SHAs from this repo's recent history
 *   - UUIDs, npm integrity hashes, and other hash-shaped strings
 *
 * NONE of these should produce any hits.
 */
import { describe, it, expect } from "vitest";
import { scrubSecrets } from "../scrub.js";

// ── cite.mjs receipt tokens (MUST survive unscathed) ──────────────────────
// Format: path:L<start>[-L<end>]@<commit7+>#<sha12+>

const RECEIPT_TOKENS = [
  // cite.mjs receipt tokens — real stamps from committed paths (verifiable by cite gate)
  "agentruntime/skills/named_to.md:L22-L29@66eb2a3#8282f9cdeb52",
  "agentruntime/skills/scent.md:L1-L10@9c2f462#6bcfe502df60",
  "agentruntime/skills/colony.md:L1-L10@9c2f462#1cbc2e89a8d0",
  "agentruntime/skills/claims_carry.md:L1-L10@9c2f462#9bfb8d3af554",
  "agentruntime/scripts/safe-commit.ps1:L1-L10@9c2f462#faf77a9f8dc6",
  "agentruntime/CLAUDE.md:L1-L10@9c2f462#0e3ab4f18966",
  // Single-line reference format (no range)
  "agentruntime/scripts/rebuild.sh:L1@9c2f462#e2b37d0fbeeb",
];

describe("false-positive corpus — cite.mjs receipt tokens (Live Proof 2)", () => {
  for (const token of RECEIPT_TOKENS) {
    it(`receipt token survives: ${token}`, () => {
      const { text, hits } = scrubSecrets(token);
      expect(hits, `unexpected hit(s) on receipt token: ${JSON.stringify(hits)}`).toHaveLength(0);
      expect(text).toBe(token);
    });
  }

  it("receipt tokens survive when embedded in a scent block comment", () => {
    const block = `// ---
    const { text, hits } = scrubSecrets(block);
    expect(hits).toHaveLength(0);
    expect(text).toBe(block);
  });
});

// ── Git SHAs from this repo's recent history ──────────────────────────────
// From: git log --oneline -5 (commit 9c2f462b and siblings)

const GIT_SHAS = [
  // 7-char (short)
  "9c2f462",
  "39800de",
  "3932e09",
  "bd8ddae",
  "d0e1500",
  // 8-char (common short)
  "9c2f462b",
  "39800de1",
  "3932e09c",
  "bd8ddaef",
  "d0e15006",
  // 40-char (full SHA-1)
  "9c2f462bc3d4e5f6a7b8c9d0e1f23456789abcde",
  // 64-char (SHA-256 / BLAKE3)
  "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4",
];

describe("false-positive corpus — git SHAs (Live Proof 2)", () => {
  for (const sha of GIT_SHAS) {
    it(`git SHA survives standalone: ${sha}`, () => {
      const { text, hits } = scrubSecrets(sha);
      expect(hits, `unexpected hits for SHA ${sha}: ${JSON.stringify(hits)}`).toHaveLength(0);
      expect(text).toBe(sha);
    });
  }

  it("git SHA survives in a commit message context", () => {
    const msg = "Reverts commit 9c2f462b (see also bd8ddaef and d0e15006)";
    const { text, hits } = scrubSecrets(msg);
    expect(hits).toHaveLength(0);
    expect(text).toBe(msg);
  });

  it("git SHA survives in a git log line", () => {
    const line = "9c2f462b chore(templates): strip name+category-noun description prefixes";
    const { text, hits } = scrubSecrets(line);
    expect(hits).toHaveLength(0);
    expect(text).toBe(line);
  });
});

// ── UUIDs ──────────────────────────────────────────────────────────────────

const UUIDS = [
  "550e8400-e29b-41d4-a716-446655440000",
  "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "a8098c1a-f86e-11da-bd1a-00112444be1e",
];

describe("false-positive corpus — UUIDs", () => {
  for (const uuid of UUIDS) {
    it(`UUID survives: ${uuid}`, () => {
      const { text, hits } = scrubSecrets(uuid);
      expect(hits).toHaveLength(0);
      expect(text).toBe(uuid);
    });
  }
});

// ── npm integrity hashes ───────────────────────────────────────────────────

const NPM_HASHES = [
  "sha512-Qm5Zrx6GZRsqvKI7GRm8HHOmkNKVreFCpovBqjkOV2eIwAAAAAAAAAAAAAAAAAAAAAA==",
  "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
  "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
];

describe("false-positive corpus — npm integrity hashes", () => {
  for (const hash of NPM_HASHES) {
    it(`npm integrity hash survives: ${hash.slice(0, 40)}…`, () => {
      const { text, hits } = scrubSecrets(hash);
      expect(hits).toHaveLength(0);
      expect(text).toBe(hash);
    });
  }
});

// ── Ordinary code tokens that contain "key" / "token" ────────────────────

describe("false-positive corpus — benign token/key variable names", () => {
  const BENIGN_CODE = [
    "const maxTokens = 4096;",
    "const tokenCount = response.usage.total_tokens;",
    "function parseToken(tokenString) { return JSON.parse(tokenString); }",
    "type ApiKeyConfig = { key: string; expires: Date };",
    "const primaryKey = row.id;",
    "console.log('token_type:', token_type);",
    "sort_key = 'created_at'",
    "primary_key = 1",
    // Short values (< 8 chars)
    "token=short",
    "password=abc123",
    "api_key=tiny",
    // Boolean / null values
    "secret=true",
    "password=false",
    "token=null",
  ];

  for (const code of BENIGN_CODE) {
    it(`benign code survives: ${JSON.stringify(code)}`, () => {
      const { text, hits } = scrubSecrets(code);
      expect(hits, `unexpected hit on benign code: ${JSON.stringify(hits)}`).toHaveLength(0);
      expect(text).toBe(code);
    });
  }
});

// ── Real-looking env file comments (no actual secrets) ───────────────────

describe("false-positive corpus — env file structure without secrets", () => {
  const ENV_SHELL = `# Environment configuration
# DO NOT commit real secrets to git

# Set these in your local .env file:
# ANTHROPIC_API_KEY=<your-key>
# GITHUB_TOKEN=<your-github-token>

# Non-secret config:
NODE_ENV=development
PORT=3000
LOG_LEVEL=info
MAX_CONNECTIONS=10
TIMEOUT_MS=30000
`;

  it("env file template with placeholder comments survives", () => {
    const { text, hits } = scrubSecrets(ENV_SHELL);
    expect(hits).toHaveLength(0);
    expect(text).toBe(ENV_SHELL);
  });
});

// ── Mixed corpus: receipt tokens + git SHAs in realistic tool output ───────

describe("false-positive corpus — mixed realistic tool output", () => {
  it("grep output containing SHAs and receipt tokens survives intact", () => {
    const output = [
      "agentruntime/src/workflows/nodes/core.ts:67:    // commit 9c2f462b hardened BUG-001",
      "agentruntime/scripts/cite.mjs:12:// Receipt: agentruntime/scripts/safe-commit.sh:L1-L10@9c2f462#3b1e8ca25977",
      "agentruntime/CLAUDE.md:42:# See also bd8ddaef and d0e15006",
      "agentruntime/package.json:15:  \"version\": \"1.0.0\",",
    ].join("\n");
    const { text, hits } = scrubSecrets(output);
    expect(hits).toHaveLength(0);
    expect(text).toBe(output);
  });

  it("git diff output with commit SHAs survives intact", () => {
    const diff = `diff --git a/src/index.ts b/src/index.ts
index 9c2f462..bd8ddae 100644
--- a/src/index.ts
+++ b/src/index.ts
@@ -1,5 +1,6 @@
 import { foo } from "./foo.js";
+import { bar } from "./bar.js";
 export { foo };
`;
    const { text, hits } = scrubSecrets(diff);
    expect(hits).toHaveLength(0);
    expect(text).toBe(diff);
  });
});
