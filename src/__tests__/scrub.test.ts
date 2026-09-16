/**
 * Unit tests for scrubSecrets — fake keys only; never real credentials.
 * All secret-shaped strings below are OBVIOUSLY FAKE (000…, TEST…, etc.).
 */
import { describe, it, expect } from "vitest";
import { scrubSecrets } from "../scrub.js";

// ── Live proof 1: ≥12 fake-secret inputs → correct kinds ──────────────────

const FAKE_CASES: Array<{ name: string; input: string; kind: string; expectRedacted: boolean }> = [
  {
    name: "Anthropic key (sk-ant-)",
    input: "key: sk-ant-api01-00000000000000000000000000000000",
    kind: "anthropic-key",
    expectRedacted: true,
  },
  {
    name: "OpenAI-style key (sk-)",
    input: "OPENAI_KEY=sk-00000000000000000000000000000000000000000000000",
    kind: "openai-key",
    expectRedacted: true,
  },
  {
    name: "xAI key",
    input: "Authorization: xai-00000000000000000000000000000000",
    kind: "xai-key",
    expectRedacted: true,
  },
  {
    name: "GitHub PAT classic (ghp_)",
    input: "token: ghp_000000000000000000000000000000000000",
    kind: "github-token",
    expectRedacted: true,
  },
  {
    name: "GitHub OAuth token (gho_)",
    input: "gho_000000000000000000000000000000000000",
    kind: "github-token",
    expectRedacted: true,
  },
  {
    name: "GitHub fine-grained PAT",
    input: "github_pat_00000000000000000000000000000000000000000000000000000000",
    kind: "github-pat",
    expectRedacted: true,
  },
  {
    name: "GitLab PAT",
    input: "CI_JOB_TOKEN=glpat-00000000000000000000",
    kind: "gitlab-pat",
    expectRedacted: true,
  },
  {
    name: "Slack bot token (xoxb-)",
    input: "slack_token=xoxb-000000000000-000000000000-00000000000000000000000000",
    kind: "slack-token",
    expectRedacted: true,
  },
  {
    name: "Google API key (AIza)",
    // AIza + exactly 35 chars = 39 total
    input: "key=AIza00000000000000000000000000000000000",
    kind: "google-api-key",
    expectRedacted: true,
  },
  {
    name: "AWS access key (AKIA)",
    input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    kind: "aws-key",
    expectRedacted: true,
  },
  {
    name: "JWT (eyJ prefix)",
    input: "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    kind: "jwt",
    expectRedacted: true,
  },
  {
    name: "Bearer token in Authorization header",
    // Non-JWT bearer value so only the bearer pattern fires (not jwt first)
    input: "Authorization: Bearer FakeLongBearerToken000000000000000000",
    kind: "bearer",
    expectRedacted: true,
  },
  {
    name: "PEM private key block",
    input: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC00000000\n-----END PRIVATE KEY-----",
    kind: "pem-block",
    expectRedacted: true,
  },
  {
    name: "credential assignment: password",
    input: "password=MySuperSecretP@ss123",
    kind: "credential",
    expectRedacted: true,
  },
  {
    name: "credential assignment: api_key (YAML)",
    // Value has non-hex chars (g, h, j, K, M, n) to avoid isBenignValue hex exclusion
    input: "api_key: FakeNonHexKeyGH789jKl012MnO",
    kind: "credential",
    expectRedacted: true,
  },
  {
    name: "credential assignment: secret (YAML — no quotes around key)",
    // JSON with quoted keys ("secret": ...) can't match our pattern (key needs bare :=)
    // YAML bare-key format works cleanly
    input: "secret: TopSecretValue9876-xyz",
    kind: "credential",
    expectRedacted: true,
  },
  {
    name: "URL secret param (access_token)",
    input: "https://api.example.com/data?access_token=fake_token_00000000000000&format=json",
    kind: "url-secret",
    expectRedacted: true,
  },
  {
    name: "URL secret param (api_key)",
    input: "curl https://maps.example.com/?api_key=FakeApiKey1234567890&query=test",
    kind: "url-secret",
    expectRedacted: true,
  },
];

describe("scrubSecrets — fake-secret detection (Live Proof 1)", () => {
  for (const tc of FAKE_CASES) {
    it(`detects ${tc.name}`, () => {
      const { text, hits } = scrubSecrets(tc.input);
      if (tc.expectRedacted) {
        expect(hits.length, `expected hits for: ${tc.input}`).toBeGreaterThan(0);
        expect(hits.some((h) => h.kind === tc.kind), `expected kind '${tc.kind}' in hits`).toBe(true);
        expect(text).toContain(`[REDACTED:${tc.kind}]`);
        expect(text).not.toContain(tc.input); // verify the original secret string is gone
      }
    });
  }
});

// ── Bearer prefix preservation ─────────────────────────────────────────────

describe("scrubSecrets — structural preservation", () => {
  it("bearer: keeps 'Authorization: Bearer ' prefix", () => {
    const { text } = scrubSecrets("Authorization: Bearer FakeLongToken000000000000000000");
    expect(text).toContain("Authorization: Bearer [REDACTED:bearer]");
  });

  it("url-secret: keeps param key, redacts value", () => {
    const { text } = scrubSecrets("https://api.example.com?token=fake_long_token_value_here");
    expect(text).toContain("?token=[REDACTED:url-secret]");
  });

  it("credential: anthropic key in assignment emits anthropic-key kind (specific wins)", () => {
    const { hits } = scrubSecrets("api_key = sk-ant-api01-00000000000000000000000000000000");
    const kinds = hits.map((h) => h.kind);
    // anthropic-key runs first and replaces the value; credential sees [REDACTED:…] which has [ excluded
    expect(kinds).toContain("anthropic-key");
  });
});

// ── Hit counting ────────────────────────────────────────────────────────────

describe("scrubSecrets — hit counting", () => {
  it("counts multiple occurrences of the same kind", () => {
    const input = [
      "ghp_000000000000000000000000000000000000",
      "ghp_111111111111111111111111111111111111",
    ].join("\n");
    const { hits } = scrubSecrets(input);
    const ghHit = hits.find((h) => h.kind === "github-token");
    expect(ghHit?.count).toBe(2);
  });

  it("counts different kinds separately", () => {
    const input = [
      "sk-ant-api01-00000000000000000000000000000000",
      "ghp_000000000000000000000000000000000000",
    ].join("\n");
    const { hits } = scrubSecrets(input);
    expect(hits.some((h) => h.kind === "anthropic-key")).toBe(true);
    expect(hits.some((h) => h.kind === "github-token")).toBe(true);
  });
});

// ── Live proof 3: idempotency + passthrough ────────────────────────────────

describe("scrubSecrets — idempotency (Live Proof 3)", () => {
  const IDEMPOTENCY_CASES = [
    "sk-ant-api01-00000000000000000000000000000000",
    "Authorization: Bearer FakeLongToken000000000000000000000000000",
    "password=MySuperSecretP@ss123\napi_key=SomeOtherFakeValue123\n",
    "ghp_000000000000000000000000000000000000\nghp_111111111111111111111111111111111111",
    "-----BEGIN PRIVATE KEY-----\nMIIFakeKeyData00000000==\n-----END PRIVATE KEY-----",
    "https://api.example.com?token=fake_long_token_value_here&other=ok",
  ];

  for (const input of IDEMPOTENCY_CASES) {
    it(`idempotent for: ${input.slice(0, 50).replace(/\n/g, "\\n")}…`, () => {
      const once = scrubSecrets(input).text;
      const twice = scrubSecrets(once).text;
      expect(twice).toBe(once);
    });
  }
});

describe("scrubSecrets — passthrough (Live Proof 3)", () => {
  const CLEAN_CASES = [
    "const maxTokens = 4096;",
    "console.log('hello world');",
    "git commit -m 'feat: add feature'",
    "(no matches)",
    "",
  ];

  for (const input of CLEAN_CASES) {
    it(`byte-identical passthrough for: ${JSON.stringify(input)}`, () => {
      const { text, hits } = scrubSecrets(input);
      expect(text).toBe(input);
      expect(hits).toHaveLength(0);
    });
  }
});

// ── Never throws ────────────────────────────────────────────────────────────

describe("scrubSecrets — never throws", () => {
  it("handles non-string input gracefully", () => {
    expect(() => scrubSecrets(null as unknown as string)).not.toThrow();
    expect(() => scrubSecrets(undefined as unknown as string)).not.toThrow();
    expect(() => scrubSecrets(42 as unknown as string)).not.toThrow();
  });

  it("handles extremely long input without throwing", () => {
    const huge = "a".repeat(1_000_000);
    expect(() => scrubSecrets(huge)).not.toThrow();
    const { text, hits } = scrubSecrets(huge);
    expect(text).toBe(huge);
    expect(hits).toHaveLength(0);
  });

  it("handles strings with unusual unicode without throwing", () => {
    const weird = "🔑 �​‮ token=abc123defghijklmnop";
    expect(() => scrubSecrets(weird)).not.toThrow();
  });
});
