# Hoshimi Localify EN

## [Submit Bug Reports Here](https://forms.gle/TZDMAieKvuFLf5ru7)

English translation module for **Idol Pride** (LSPatch). This repository builds and
releases the module app; users patch their own game — no patched game is distributed here.

This is a **modified derivative** of Hoshimi Localify (GPL-3.0) — see *Upstream & credits*.

## Requirements

- **Idol Pride, the Japanese client**, installed from Google Play
  (`game.qualiarts.idolypride`). The Korean and global builds are different apps and are not
  supported.
- **Android 10+** (the module targets `minSdk` 29). Tested on a Moto G (Android 14, arm64);
  any arm64 device should work.
- **Patching privileges — one of:**
  - a **rooted** device: LSPatch manages modules through root, no computer needed; **or**
  - an **unrooted device plus a computer**: a PC with `adb` (Android SDK platform-tools), a
    USB cable, and *USB debugging* turned on in **Developer options**.
- **LSPatch manager** — `manager.apk` (package `org.lsposed.lspatch`) from the official
  [JingMatrix/LSPatch](https://github.com/JingMatrix/LSPatch) release.
- **Shizuku** — from [RikkaApps/Shizuku](https://github.com/RikkaApps/Shizuku). The manager
  needs Shizuku to patch without root (start it over ADB, over root, or — on Android 11+ —
  over wireless debugging).
- **The module APK** from this repo's [releases](../../releases):
  `HoshimiLocalify-en-lite-<ver>.apk` (recommended) or
  `HoshimiLocalify-en-full-<ver>.apk` (adds the breast-physics parameters).
- ~40 MB of free storage for the translation data, plus room for the patched game.
- An internet connection.

## Install (patch the game yourself)

1. **Install the LSPatch manager.** Copy `manager.apk` to the phone and install it (allow
   "install unknown apps" for your file manager), or
   `adb install manager.apk`.
2. **Install and start Shizuku.** Open Shizuku and tap **Start**; it prints the exact command
   for your device, for example over ADB from your computer:
   ```bash
   adb shell /data/app/~~.../moe.shizuku.privileged.api-.../lib/arm64/libshizuku.so
   ```
   On Android 11+ you can instead pair over wireless debugging, or start via root. Wait for
   "Shizuku is running".
3. **Grant LSPatch access to Shizuku.** Open the manager; it asks for Shizuku permission —
   grant it.
4. **Install the module APK.** Install `HoshimiLocalify-en-lite-<ver>.apk` (use
   `-full-` if you want the breast-physics parameters). The app appears as
   **Hoshimi Localify EN**.
5. **Patch the game.** In the manager: **New Patch → Local mode → Select an installed app →
   Idol Pride**, then install the patched app it produces. LSPatch re-signs the APK, so
   **uninstall the Play build of Idol Pride first** (your account and progress are on the
   server, so this only costs a re-login).
6. **Enable the module for the patched game.** Back in the manager, open **Apps → Idol Pride**
   and switch **Hoshimi Localify EN** **on** in its module list. LSPatch only loads modules
   that are enabled for a given app, so the translation does nothing until this is on.
   Relaunch the game if it was already open.
7. **Fetch the translations.** Open **Hoshimi Localify EN → Home**; it downloads the data
   (~35–40 MB, roughly 4350 files) from
   [`tokanada/ipr-translation-data-en`](https://github.com/tokanada/ipr-translation-data-en)'s
   latest release and reports the current resource version.
8. **Play.** The game's menus, story, and master-data text now render in English.
9. **Updating later** — from the same **Home** tab. Data updates need **no re-patch**.

## Warnings

- **Uninstall the store game first.** LSPatch re-signs the APK, so the patched build cannot
  be installed over the store build. Your account is server-side; this costs a re-login only.
- **In-app purchases will not work.** The patched build is not Play-signed, so Google Play
  billing fails. Everything else — account, progress, and purchases already made — is
  server-side and unaffected.
- **Keep the LSPatch manager (and Shizuku) installed.** Local mode is bound to the manager;
  removing either breaks module loading.
- **Never install the KR module** (`io.github.cylear.hoshimi.localify`) alongside this one —
  identical package id, only one can be active.
- Each live-client version bump needs a re-verify pass.

## Upstream & credits

This repository is a **modified derivative** of **Hoshimi Localify** (GPL-3.0). Original
code and prior work:

- **Chinosk6** — [gakuen-imas-localify](https://github.com/chinosk6/gakuen-imas-localify) (original code)
- **Vilebbit** — [HoshimiToolkit](https://github.com/Vilebbit/HoshimiToolkit), [SolisClient](https://github.com/Vilebbit/SolisClient)

Changes made here: English translation data wiring, `full`/`lite` build flavors, the public
update flow, and narrowing the module scope to the JP client. Not affiliated with Idolm@ster
or Bandai Namco.

## License

GPL-3.0. As a modified derivative of a GPL-3.0 work, this repository is distributed under the
same license. See `LICENSE`.

## Source / sync

This repo is a snapshot of a private source-of-truth fork. See `SYNC.md`.
