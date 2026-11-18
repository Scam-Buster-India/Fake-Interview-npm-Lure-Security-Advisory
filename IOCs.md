# Indicators of Compromise (IOCs)

**Advisory:** Fake-Interview npm Lure · **Published by:** Scam Buster India · **Date:** 18 November 2026
**Method:** static analysis only. Nothing was executed and no server was contacted.

> ⚠️ IPs and URLs below are **defanged** (`[.]`). Re-fang only inside a controlled tool (SIEM, firewall rule, blocklist). **Never** open or request these addresses from a normal machine.
>
> ⚠️ An IOC match means "look closer", not "proven compromised". Servers rotate, and a payload may never have been served to a given victim.

---

## 1. Packages

| Type | Name | Version | Notes |
|---|---|---|---|
| Public npm loader | `motionframe-plugins` | `1.0.7` (project asks `^1.0.7`) | Required from `tailwind.config.js`. Declares the private dependency below. |
| Private scoped npm package | `@motionlib/framer-motion` | `1.0.6` | `publishConfig.access = restricted`. Returns 404 publicly without a token. Contains the payload. |
| Claimed repository (metadata only) | `github.com/rueppipep/postcss-motion-animation` | n/a | Written in package metadata. **May be fake or impersonated.** Do not treat the GitHub user as proven operator. |
| Claimed author (metadata only) | `rueppipep` | n/a | Same caveat. |

## 2. Files and hashes

| File | Size | SHA-256 |
|---|---|---|
| `src/config.js` (inside `@motionlib/framer-motion@1.0.6`) | 158,936 bytes | `cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743` |
| `@motionlib/framer-motion@1.0.6` tarball (`.tgz`) | n/a | `b7418afce88c51717fd134ab82eb0a7571fc402c4286ebdc4404a67b78af5e6d` |
| `full-stack-assignment.7z` (lure archive) | 1,019,444 bytes | `2db16f7d821af983b39be1ab2a838a4cc13bf038fab710dc6047177a6f6ed227` |

Tarball layout: `package/{package.json, index.js, README.md, LICENSE, src/config.js, src/transform.js}`

## 3. Network indicators (defanged)

| Indicator | Type | Detail |
|---|---|---|
| `216[.]126[.]231[.]70:1224` | IP:port | Primary C2 candidate |
| `153[.]75[.]88[.]215:1224` | IP:port | Secondary C2 candidate |
| `/debugCheck` | URL path | HTTP **POST**, query `?id=<delay>,<duration>,<iterationCount>` |
| `hxxp://216[.]126[.]231[.]70:1224/debugCheck?id=…` | URL pattern | Plain HTTP (no TLS) |
| `hxxp://153[.]75[.]88[.]215:1224/debugCheck?id=…` | URL pattern | Plain HTTP (no TLS) |

Behaviour: up to **5 attempts per endpoint**, **60 s** timeout each. Server reply is JSON; field `message` is base64-decoded and run with `new Function('require', code)(require)`.

## 4. Host and file indicators

| Indicator | Where | Meaning |
|---|---|---|
| `//registry.npmjs.org/:_authToken=npm_…` in a project `.npmrc` | Project root | Committed npm token (not published here). Strong red flag in an unsolicited repo. |
| `audit=false` + `fund=false` + `loglevel=error` + `progress=false` in `.npmrc` | Project root | Suppresses warnings and noise |
| `require('motionframe-plugins')` inside `try/catch` in `tailwind.config.js` | Project root | Loader trigger |
| `console.warn('[tailwind] flexible-layout-tools not installed; skipping plugin.')` | `tailwind.config.js` | Misleading message that names an **unrelated** package |
| `Tailwind engine failed to load after all retries` | Terminal output | Printed when all C2 attempts fail |
| `node_modules/@motionlib/framer-motion/` | Developer machine | Presence means the private package was installed |
| `node_modules/motionframe-plugins/` | Developer machine | Presence means the loader was installed |

## 5. Code patterns (for YARA / grep / SAST rules)

```text
new Function('require'
Buffer.from(<x>, 'base64').toString('utf8')
fetch(<url>, { method: 'POST', signal: ... })
/debugCheck
['A6MTIyNA==MjE2LjEyNi4yMzEuNz','IxNToxMjI0MTUzLjc1Ljg4Lj']   <- rotated base64 endpoint strings
```

The endpoint strings are decoded by: take the string, move the first 10 characters to the end, base64-decode, lowercase.

## 6. Behavioural indicators

- Node.js process (`next dev` / `next build` / `tailwindcss`) makes an **outbound HTTP POST to a bare IP on port 1224** shortly after start.
- `npm install` fails with **404** on `@motionlib/framer-motion` when no token is present.
- Unpaid pre-contract "assessment", Drive-hosted 7z, request to upload results to a **public** link, and a refusal to use platform payment protection.

## 7. Machine-readable block

```json
{
  "advisory": "fake-interview-npm-lure-kontrora",
  "published": "2026-11-18",
  "publisher": "Scam Buster India",
  "contact": "security@scambuster.ind.in",
  "analysis": "static-only",
  "compromise_established": false,
  "packages": [
    { "ecosystem": "npm", "name": "motionframe-plugins", "version": "1.0.7", "role": "public-loader" },
    { "ecosystem": "npm", "name": "@motionlib/framer-motion", "version": "1.0.6", "role": "private-payload", "access": "restricted" }
  ],
  "files": [
    { "name": "src/config.js", "size": 158936, "sha256": "cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743" },
    { "name": "motionlib-framer-motion-1.0.6.tgz", "sha256": "b7418afce88c51717fd134ab82eb0a7571fc402c4286ebdc4404a67b78af5e6d" },
    { "name": "full-stack-assignment.7z", "sha256": "2db16f7d821af983b39be1ab2a838a4cc13bf038fab710dc6047177a6f6ed227" }
  ],
  "network": [
    { "type": "ipv4:port", "value": "216.126.231.70:1224", "defanged": "216[.]126[.]231[.]70:1224", "path": "/debugCheck", "method": "POST", "scheme": "http" },
    { "type": "ipv4:port", "value": "153.75.88.215:1224", "defanged": "153[.]75[.]88[.]215:1224", "path": "/debugCheck", "method": "POST", "scheme": "http" }
  ],
  "techniques": ["T1195.002 Supply Chain Compromise: Compromise Software Supply Chain", "T1059.007 Command and Scripting Interpreter: JavaScript", "T1105 Ingress Tool Transfer", "T1027 Obfuscated Files or Information"]
}
```

## 8. Change log

| Date | Change |
|---|---|
| 2026-11-18 | Initial publication |

Found a new related sample or a correction? **security@scambuster.ind.in**
