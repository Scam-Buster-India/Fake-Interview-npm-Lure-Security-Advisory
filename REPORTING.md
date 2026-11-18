# How to Report This

**Advisory:** Fake-Interview npm Lure · **Scam Buster India** · 18 November 2026

Received this lure, or found these packages in a project? Reporting takes about 10 minutes and helps stop the next victim. Each recipient below handles a different part of the problem, so a short report to each works best.

> Replace anything in `<angle brackets>` with your own details. Use the **defanged** IPs exactly as written, and never open them.

## Who to report to

| # | Recipient | What it achieves | Where |
|---|---|---|---|
| 1 | **npm** | Takedown of `motionframe-plugins` and `@motionlib/framer-motion`; revocation of the committed token; review of the publisher account | Package page of `motionframe-plugins` → **Report malware** |
| 2 | **The platform where you were contacted** (Fiverr, LinkedIn, Upwork, etc.) | Removes the client account and warns other freelancers | Report button in the conversation, or the platform's support form |
| 3 | **Google Drive** (if the archive was shared by a Drive link) | Removes the hosted archive | Open the shared link → ⋮ menu → **Report abuse** |
| 4 | **CERT-In (India)** | National incident record and blocklisting | `incident@cert-in.org.in` |
| 5 | **National Cyber Crime Portal (India)** | Official complaint on record | [cybercrime.gov.in](https://cybercrime.gov.in) · helpline **1930** |
| 6 | **OpenSSF malicious-packages** | Gets the packages into OSV so scanners flag them | Contribution/report process of the `ossf/malicious-packages` repository on GitHub |

Outside India, report to your national CERT or cybercrime authority instead of 4 and 5.

## Before you report

**Do**
- Quote the hashes, package names/versions and defanged IPs from [`IOCs.md`](IOCs.md).
- Keep the original archive and your chat export offline and unmodified. Platforms and police may ask for them.
- Say clearly what you did and did not do (for example: "I did not run it", or "I ran `npm run dev` on `<date>`").

**Don't**
- Don't post the npm token (if you have the archive) in any public place. If you want it revoked, send it **privately** to npm security or the police.
- Don't reuse or test the token. It belongs to someone else's account.
- Don't contact the IPs or run the payload "to see what happens".
- Don't name or harass any person or company based on this evidence. The "Kontrora" brand and the GitHub username in the package metadata may be impersonated.

If you **ran** the project, do [`DETECTION.md`](DETECTION.md) section B first, then report.

---

## Copy-paste templates

### 1. npm (Report malware)

```text
Hello npm Security,

I am reporting malware in these packages:
- Public: motionframe-plugins@1.0.7
- Private/scoped (restricted access): @motionlib/framer-motion@1.0.6

motionframe-plugins declares @motionlib/framer-motion@1.0.6 as a runtime dependency. The private package's src/config.js
(SHA-256 cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743) is obfuscated. It sends an HTTP POST to hard-coded
servers, base64-decodes the "message" field of the JSON reply and runs it with new Function('require', code)(require),
which gives the server arbitrary code execution in the victim's Node.js process. There is no install script: the code runs when
tailwind.config.js loads the plugin (npm run dev / npm run build), so --ignore-scripts does not protect users.

Endpoints (defanged): 216[.]126[.]231[.]70:1224 and 153[.]75[.]88[.]215:1224, path /debugCheck (POST).
Tarball SHA-256 (@motionlib/framer-motion@1.0.6): b7418afce88c51717fd134ab82eb0a7571fc402c4286ebdc4404a67b78af5e6d

Distribution: fake "coding assignment" archive (SHA-256 2db16f7d821af983b39be1ab2a838a4cc13bf038fab710dc6047177a6f6ed227)
whose .npmrc contains a plaintext npm token so the private package resolves.

Please remove/disable both packages, revoke the committed token and review the publishing account(s).

Technical advisory: <ADVISORY LINK>
My situation: <e.g. "I received this archive on <date> and did not run it">
Contact: <YOUR EMAIL>
```

### 2. Platform where you were contacted (Fiverr / LinkedIn / Upwork …)

```text
Hello Trust & Safety,

I am reporting an account that sent me a malicious "coding assignment".

Account: <USERNAME / PROFILE LINK> · Dates: <DATES>

Pattern: offered a well-paid contract, then asked for an unpaid practical task before any contract, declined the platform's paid
order option, and sent an archive via <Google Drive / other link>. The archive's dependencies (npm: motionframe-plugins ->
private @motionlib/framer-motion) download and execute remote code when the dev server or build runs.

Archive SHA-256: 2db16f7d821af983b39be1ab2a838a4cc13bf038fab710dc6047177a6f6ed227
Technical advisory: <ADVISORY LINK>

Please investigate this account and related accounts for similar outreach. I can provide the chat export on request.
```

### 3. Google Drive abuse report

```text
This file is a malware lure: an archive (SHA-256 2db16f7d821af983b39be1ab2a838a4cc13bf038fab710dc6047177a6f6ed227) sent to freelancers as a
"coding assignment". It contains a project whose dependencies fetch and execute remote JavaScript. Details: <ADVISORY LINK>
```

### 4. CERT-In (`incident@cert-in.org.in`)

**Subject:** Incident report: malicious npm supply-chain lure targeting freelance developers

```text
Respected Sir/Madam,

I wish to report a malware-delivery attempt targeting freelance developers.

Reporter: <NAME> · <EMAIL> · <PHONE>
Date: <DATE>
Type: Malicious software package / social-engineering lure (fake job assessment)
Vector: A fake client sent an archive of a Next.js project. Its dependencies (npm: motionframe-plugins@1.0.7 -> private
        @motionlib/framer-motion@1.0.6) fetch and execute JavaScript from a remote server when the dev server/build runs.
Indicators: 216[.]126[.]231[.]70:1224, 153[.]75[.]88[.]215:1224 (HTTP POST /debugCheck);
        payload file SHA-256 cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743;
        archive SHA-256 2db16f7d821af983b39be1ab2a838a4cc13bf038fab710dc6047177a6f6ed227
My status: <e.g. "Not executed" / "Executed on <date>; no suspicious activity found so far">
Full advisory and IOCs: <ADVISORY LINK>

Request: please add the indicators to national advisories/blocklists and coordinate with npm/hosting providers as appropriate.

Regards,
<NAME>
```

### 5. cybercrime.gov.in (complaint text)

```text
Category: Other cyber crime / Malware-related attempt.
Summary: A person using a <PLATFORM> account asked me to complete an unpaid coding task from an archive sent via <LINK TYPE>.
The archive contained a hidden remote-code-execution loader (npm packages motionframe-plugins and @motionlib/framer-motion)
that downloads and runs attacker-controlled code from 216[.]126[.]231[.]70:1224 / 153[.]75[.]88[.]215:1224.
Loss/impact: <none / describe>. Technical details: <ADVISORY LINK>
Suspect details: <USERNAME>; <LINK>.
```

### 6. OpenSSF malicious-packages / OSV

```text
Ecosystem: npm
Packages: motionframe-plugins (1.0.7; affected versions to be confirmed), @motionlib/framer-motion (1.0.6, private/restricted)
Type: Malicious code - remote code execution (fetch + base64 decode + new Function)
Evidence: src/config.js SHA-256 cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743;
          tarball SHA-256 b7418afce88c51717fd134ab82eb0a7571fc402c4286ebdc4404a67b78af5e6d
C2 (defanged): 216[.]126[.]231[.]70:1224, 153[.]75[.]88[.]215:1224 /debugCheck
Context: fake-interview lure; same technique family as MAL-2026-17665/17666/17667 (technique similarity only; no link to the
         same operator is claimed).
Advisory: <ADVISORY LINK>
```

---

Questions, or want the withheld evidence for your report? **security@scambuster.ind.in**
