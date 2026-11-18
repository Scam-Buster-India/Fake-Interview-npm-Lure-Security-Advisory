# Evidence

**Advisory:** Fake-Interview npm Lure · **Scam Buster India** · 18 November 2026

Everything here is **redacted** and was produced by **static analysis only**: extraction, hashing and text inspection. No project command, package install, dev server, build or downloaded package code was executed, and no request was sent to the decoded endpoints.

## Published files

| File | What it shows |
|---|---|
| [`package-json-excerpt.json`](package-json-excerpt.json) | The lure project's `package.json`, trimmed to the relevant parts: `motionframe-plugins@^1.0.7`, the `dev`/`build` scripts, and the fact that there is no install script |
| [`tailwind-plugin-load.txt`](tailwind-plugin-load.txt) | `tailwind.config.js` plugin block: `require('motionframe-plugins')` inside `try/catch`, errors swallowed, warning names an unrelated package |
| [`npmrc-redacted.txt`](npmrc-redacted.txt) | The `.npmrc` with the **token removed**: shows the token line format and the warning-suppression settings |
| [`private-package-metadata.json`](private-package-metadata.json) | `package.json` of `@motionlib/framer-motion@1.0.6`: `restricted` access, claimed repository/author (unverified) |
| [`obfuscated-runtime-excerpt.txt`](obfuscated-runtime-excerpt.txt) | Short excerpt of the obfuscated loader showing the fetch → base64 decode → `new Function('require', …)(require)` chain |
| [`decoded-endpoints.txt`](decoded-endpoints.txt) | Static decode of the two rotated-base64 endpoint strings |
| [`SHA256SUMS.txt`](SHA256SUMS.txt) | Hashes of every published file and of the withheld artifacts |

## Verify the published files

```bash
cd evidence
grep -v '^#' SHA256SUMS.txt | grep -v WITHHELD | grep -v '^$' | sha256sum -c -
# macOS: use shasum -a 256 -c instead of sha256sum -c
```

## Deliberately withheld

| Artifact | Why | SHA-256 |
|---|---|---|
| `full-stack-assignment.7z` (original lure) | Contains a live npm token and is a working lure | `2db16f7d821af983b39be1ab2a838a4cc13bf038fab710dc6047177a6f6ed227` |
| Original `.npmrc` | Plaintext npm token. Publishing it would let anyone use the operator's credential | n/a |
| `@motionlib/framer-motion@1.0.6` tarball | Full working payload loader | `b7418afce88c51717fd134ab82eb0a7571fc402c4286ebdc4404a67b78af5e6d` |
| `src/config.js` (full file, 158,936 bytes) | Complete obfuscated payload | `cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743` |
| Chat screenshots/exports | Contain account identities | n/a |

### Requesting withheld artifacts

Verified researchers and platform security teams (npm/GitHub, Fiverr, Google, CERT-In, OpenSSF, AV/EDR vendors): email **security@scambuster.ind.in** from an organisational address, say what you will do with the material, and we will share it over a secure channel.

### Proving we hold the originals

Hashes above are published so anyone who obtains the same files can confirm they match. On request we can additionally prove possession by hashing a salt you provide together with the original file (`sha256(salt || file)`), without sending the file.

## Limits

- Hashes prove **which file** was analysed, not **who** operated it.
- Package metadata (author, repository) is unverified and may be fake.
- The payload the server would return is **unknown**; we make no claim that any victim was compromised.
