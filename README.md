# secret-scrub

Pure, dependency-free secrets redactor: scan tool output for API keys, JWTs, PEM blocks, bearer tokens, and credential assignments; replace with [REDACTED:<kind>] tokens before the model sees them. Sibling to token-funnel — scrub runs first, then compress.

## Install

```bash
npm install secret-scrub
```  

## License

MIT
