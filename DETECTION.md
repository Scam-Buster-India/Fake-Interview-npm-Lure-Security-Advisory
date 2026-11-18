# Detection & Response Guide

**Advisory:** Fake-Interview npm Lure · **Scam Buster India** · 18 November 2026

This guide has two parts: **A. checks that run nothing** (safe), and **B. what to do if you already ran the project**.

> **Golden rule:** do not run `npm install`, `npm run dev`, `npm run build`, `npx` or `next` inside the suspicious folder while checking. Use read-only commands only.

---

## A. Safe checks: I only *received* the repo and haven't run it

### A1. Look for the packages and the token

**macOS / Linux**
```bash
cd /path/to/unzipped/project
grep -rn "motionframe-plugins\|@motionlib" package.json package-lock.json yarn.lock pnpm-lock.yaml tailwind.config.* 2>/dev/null
grep -n "_authToken" .npmrc 2>/dev/null | sed -E 's/(_authToken=).*/\1[HIDDEN]/'
```

**Windows PowerShell**
```powershell
Select-String -Path package.json,package-lock.json,yarn.lock,pnpm-lock.yaml,tailwind.config.* -Pattern "motionframe-plugins|@motionlib" -ErrorAction SilentlyContinue
(Get-Content .npmrc -ErrorAction SilentlyContinue) -replace '(_authToken=).*','$1[HIDDEN]' | Select-String "_authToken"
```

A match means: **stop**. Do not install. Delete the folder, or keep it in a locked archive only if you plan to report it.

### A2. Generic red flags in any take-home repo (even with other package names)

```bash
cat .npmrc 2>/dev/null | sed -E 's/(_authToken=).*/\1[HIDDEN]/'     # tokens, custom registries
grep -n "postinstall\|preinstall\|prepare" package.json              # install scripts
grep -n "new Function\|eval(\|child_process" tailwind.config.* next.config.* postcss.config.* vite.config.* webpack.config.* 2>/dev/null
grep -rn "registry=" .npmrc ~/.npmrc 2>/dev/null                     # non-default registry
```

Be suspicious of:
- a committed `.npmrc` with an `_authToken`
- a plugin `require`d inside `try/catch` that **swallows errors**
- warnings that name a package that is not actually in the config
- dependencies you cannot find on https://www.npmjs.com (404 = private)

### A3. Remember: `--ignore-scripts` does not help here

The loader runs when **Tailwind loads its config** (dev server or build), not through an npm lifecycle script.

---

## B. I already ran it (`npm install` + `npm run dev` / `build`)

Assume **possible compromise** until proven otherwise. The payload served by the remote server is unknown, so we cannot say exactly what it did.

### B1. Stop the bleeding (first 10 minutes)

1. **Disconnect** the machine from the network (Wi-Fi off, unplug Ethernet).
2. Close the dev server and terminals. Do **not** log in to anything else on this machine.
3. **Do not delete the folder yet.** Copy it (and `~/.npm/_logs`) to an external drive for evidence. Evidence is useful for reporting.
4. From a **different, clean device** (phone is fine), start the rotation in section B4.

### B2. Check whether the machine is infected

**Was the private package installed?**
```bash
ls node_modules/@motionlib/framer-motion 2>/dev/null && echo "PRIVATE PACKAGE PRESENT"
ls node_modules/motionframe-plugins 2>/dev/null && echo "LOADER PRESENT"
sha256sum node_modules/@motionlib/framer-motion/src/config.js 2>/dev/null   # macOS: shasum -a 256
# match = cddec7017154aebf01b317099add0b2d0adc2d1a964f601816f03782db00a743
```
```powershell
Test-Path node_modules\@motionlib\framer-motion
Get-FileHash node_modules\@motionlib\framer-motion\src\config.js -Algorithm SHA256
```

**Did it try to reach the servers? (Run while offline, these only read local state.)**
```bash
# Linux/macOS: current connections (only meaningful if you haven't rebooted)
lsof -nP -i 2>/dev/null | grep -E "216\.126\.231\.70|153\.75\.88\.215"
netstat -an 2>/dev/null | grep -E "216\.126\.231\.70|153\.75\.88\.215|:1224"

# Look in logs/history
grep -rE "216\.126\.231\.70|153\.75\.88\.215|debugCheck" ~/.npm/_logs ~/.bash_history ~/.zsh_history 2>/dev/null
grep -rn "Tailwind engine failed to load" . 2>/dev/null | head
```
```powershell
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -in "216.126.231.70","153.75.88.215" }
netstat -ano | findstr "216.126.231.70 153.75.88.215 :1224"
Select-String -Path "$env:LOCALAPPDATA\npm-cache\_logs\*" -Pattern "216.126.231.70|153.75.88.215|debugCheck" -ErrorAction SilentlyContinue
```

**Check your router / firewall / DNS / ISP logs** for outbound traffic to the two IPs on port **1224** around the time you ran the project. This is the strongest evidence of whether the loader reached its server.

**Interpretation**

| What you see | Meaning |
|---|---|
| Never ran `npm install`/`run dev`/`build` | Not affected |
| `npm install` failed with 404 on `@motionlib/framer-motion` and you never added the token | Loader could not fetch payload. Low risk, still delete the project |
| Package installed + `npm run dev`/`build` ran + **no** traffic to the IPs | Probably not served a payload, but you cannot prove it. Rotate key secrets anyway |
| Package installed + traffic to the IPs on :1224 | **Treat as compromised.** Do full B3 and B4 |

### B3. Look for persistence and leftovers (informational; a clean result does not prove safety)

**macOS / Linux**
```bash
crontab -l; ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null   # macOS
systemctl --user list-unit-files 2>/dev/null | grep enabled                                           # Linux
cat ~/.ssh/authorized_keys 2>/dev/null                    # unknown keys?
ls -lat ~ | head -20; ls -lat /tmp | head -20             # recently created files
ps aux | grep -i node | grep -v grep                      # unexpected long-running node processes
```

**Windows**
```powershell
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName,TaskPath
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Get-Process node -ErrorAction SilentlyContinue
```

Also review browser extensions, shell profile files (`.zshrc`, `.bashrc`, PowerShell `$PROFILE`) and recent GitHub / Google / cloud "new login" and "new device" notifications.

**If anything looks wrong, the safest path is to back up documents (not executables), wipe the OS and reinstall.** Antivirus scans alone are not enough for a script-based payload.

### B4. Rotate secrets (from a **clean** device, in this order)

| Priority | Rotate / review | How |
|---|---|---|
| 1 | **Email** (primary + recovery) | New password, sign out all sessions, review forwarding rules |
| 2 | **Password manager** master password + vault sessions | Sign out everywhere |
| 3 | **Banking / UPI / crypto exchanges** | Change passwords, review devices. Move wallet funds with a **new** seed if a hot wallet was on the machine |
| 4 | **GitHub / GitLab** | Revoke PATs and SSH keys, review "Sessions" and "Security log", check recent pushes |
| 5 | **npm** | Revoke tokens, enable 2FA, review recent publishes |
| 6 | **Cloud** (AWS / GCP / Azure / Vercel / Supabase / Firebase) | Rotate access keys and service-role keys, check audit logs |
| 7 | **SSH keys** | Generate new keys, remove old public keys from servers and Git hosts |
| 8 | **`.env` files and API keys** | Rotate every secret that was on the machine (Stripe, OpenAI, SMTP, DB URLs, etc.) |
| 9 | **Browser** | Sign out all sessions, change saved passwords for key sites, remove unknown extensions |
| 10 | **Fiverr / LinkedIn / Upwork** | Change password, enable 2FA, review sessions |

Turn on **2FA with an authenticator app or passkey** (not SMS) wherever you can.

### B5. After you are clean

1. Report (see [`REPORTING.md`](REPORTING.md)) and keep a copy of what you sent.
2. Keep evidence: archive hash, chat export, `~/.npm/_logs`, firewall logs.
3. Do future take-home tests only in a **throwaway VM/container** with no personal credentials and no access to your home folder.

---

## C. Safe way to inspect a suspicious repo

```bash
# Inspect first (read-only)
7z l suspicious.7z                    # list contents, extract nothing yet
mkdir /tmp/inspect && cd /tmp/inspect && 7z x ../suspicious.7z
cat package.json .npmrc tailwind.config.* next.config.* 2>/dev/null

# If you must run it: disposable VM or container with NO personal credentials and NO network
docker run --rm -it --network none -v "$PWD":/work:ro node:22 bash
```

Remember that without network the app will not install either, so use read-only inspection for the decision, and a **throwaway cloud VM** if you truly need to run it.

---

Questions or a suspected case: **security@scambuster.ind.in**
🇮🇳 India: [cybercrime.gov.in](https://cybercrime.gov.in) · helpline **1930** · CERT-In `incident@cert-in.org.in`
