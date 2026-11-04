# HoshimiLocalify-sr (private fork)

This is a private fork of [`tokanada/HoshimiLocalify-en`](https://github.com/tokanada/HoshimiLocalify-en)
that adds **private-server redirect support** for [sumire-sr](../sumire-sr) — a local
IDOLY PRIDE server. It lets the mod point the game's API, Octo catalog and master-data
downloads at a user-configured server and trust that server's CA, replacing the Frida
`e2e_hooks.js` redirect on rooted devices and (later) making the same setup work rootless
through LSPatch.

## Remotes

| Remote | URL | Purpose |
|---|---|---|
| `origin` | `https://github.com/tokanada/HoshimiLocalify-sr` | This private fork |
| `upstream` | `https://github.com/tokanada/HoshimiLocalify-en` | Public EN mod |

The first commit on `main` is the upstream tree (`433613c`) plus only `FORK.md`, so the
fork started from a clean, fast-forwardable state.

## Syncing with upstream

Use **merge, never rebase**, so the branch history stays suitable for a PR back upstream:

```bash
git fetch upstream
git merge upstream/main
```

Resolve conflicts in favour of upstream and re-apply the small additive edits listed below.
Do not reformat or reorder upstream code while resolving.

## Upstream PR plan

Once sumire-sr is public, open a PR from `HoshimiLocalify-sr:main` into
`HoshimiLocalify-en:main`. The PR should contain only the isolated changes described below,
with the private-server code gated behind a config switch that defaults to off, so the
feature is inert for ordinary users.

## Keeping the fork mergeable

All new logic lives in **new files**:

- `app/src/main/cpp/HoshimiLocalify/PrivateServer.hpp`
- `app/src/main/cpp/HoshimiLocalify/PrivateServer.cpp`
- `app/src/main/java/io/github/cylear/hoshimi/localify/PrivateServerTrust.kt`
- `app/src/main/java/io/github/cylear/hoshimi/localify/PrivateServerRedirect.kt`
- `app/src/main/java/io/github/cylear/hoshimi/localify/ui/pages/subPages/PrivateServerPage.kt`

Edits to upstream files stay small and additive:

- a `#include` plus a single `PrivateServer::Install(hookInstaller);` call in
  `StartInjectFunctions` (`app/src/main/cpp/HoshimiLocalify/Hook.cpp`);
- the new config fields (native `Config.hpp`/`Config.cpp`, `IdolyprideConfig.kt`,
  `ConfigUpdateListener.kt`);
- one navigation entry / settings section for the new page;
- the new `.cpp` in `CMakeLists.txt` (only if sources are listed explicitly);
- strings in `values/` and `values-ko/`.

Keep the same `applicationId` and package: the fork's APK replaces the `-en` build on the
device, so two modules never hook the game at once.

## What the feature does

Settings (off by default):

| Setting | Meaning |
|---|---|
| Enable private server | Master switch; hooks are only installed when on |
| Server URL | `https://<server IPv4>:<port>`, e.g. `https://192.168.0.67:8443` |
| Server CA PEM | PEM of the private server's CA (one or more certificates) |

When enabled, preserve-host mode is used whenever the Server URL host is an IPv4 address.

How it works (preserve-host mode):

- The game keeps its real hostnames (`api.game-idolypride.jp`, `climaster.game-idolypride.jp`, `api.octo-cloud.com`), so TLS SNI and the certificate CN still match the server cert (CN=api.game-idolypride.jp). Unity's TLS (UnityWebRequest) checks the CN only, not IP SANs, which is why URLs are not rewritten.
- Native hooks in `PrivateServer.cpp`: `getaddrinfo` resolves exactly those hosts (exact match; Firebase-unrelated Google hosts, `id.qseed.jp` and the CloudFront CDN are untouched) to the configured server address. `connect` rewrites `<server address>:443` to the configured port, because Rust's resolver (gRPC/YAHA) discards the resolved port and uses 443. The `GetHost` and `OctoSettings.url` overrides are disabled in this mode.
- gRPC trust: the configured CA is prepended to `Api.GetSSLRootCertificates()`.
- UnityWebRequest trust (rootless): libunity loads its root list over JNI (KeyStore "AndroidCAStore" → TrustManagerFactory → `X509TrustManager.getAcceptedIssuers()` → `getEncoded`). `PrivateServerTrust.kt` hooks `getAcceptedIssuers` and appends the configured CA (seen in logs as "augmented 143 -> 144"). It never changes `checkServerTrusted` for these hosts. Side effect: the extra issuer is visible to any code in the game process that lists accepted issuers.
- CA cache: the CA is cached at `files/hoshimi-private-server-ca.pem` in the game's data, with an "enabled" marker, so launches from the home screen work. A cache is trusted only if it is marked enabled and is less than 30 days old. It is deleted as soon as a disabled or blank config reaches the game. Known gap: the first home-screen launch right after you turn the feature off can still trust the old CA until the config arrives. It only adds an issuer; it never blocks official servers.
- The native `CertificateHandler` attach is kept as a fallback, but on 6.0.3 the surface is incomplete ("CertificateHandler surface ctor=yes create=no attach=none"), so it isn't used.

### Java-side (Firebase Auth) redirect

Firebase Auth on Android is the Java SDK, called over JNI from the Unity Firebase C++ SDK, so
the native `getaddrinfo`/`connect` hooks never see it. `PrivateServerRedirect.kt` closes that
gap; it is armed from `PrivateServerTrust` with the same enabled switch, server URL and CA and
has no settings of its own. The trust fallback never blanket-trusts: it accepts a chain only
when it validates (PKIX, revocation off) against a trust store built exclusively from the
configured private-server CA, and otherwise rethrows the platform verdict. Hosts are listed in
`BASE_REDIRECT_HOSTS` and must stay in sync with `g_redirectHosts` in `PrivateServer.cpp`.

## Private-server setup for players

1. Rooted with LSPosed: install this APK and enable it for `game.qualiarts.idolypride`. No root: patch the game with LSPatch and embed the module, e.g. `java -jar lspatch.jar <game>.apk -m app-full-debug.apk -l 2 -o out`, then install the patched game and this APK (the module app). The signatures differ from the stock game and the `-en` module, so uninstall those first; that deletes their local data.
2. In the mod app's Private server page, set **Server URL** to `https://<server IPv4>:<port>`, e.g. `https://192.168.0.67:8443`. It must be an IPv4 address to get preserve-host mode. The phone must be able to reach it directly (LAN); no adb tunnel is needed.
3. **Server CA PEM**: the whole of `sumire-sr/tls/ca.crt`.
4. Turn it on, force-stop the game, and launch from the mod app (the config travels in the `iprData` extra). Home-screen launches then work through the cached CA.
5. Server side: run sumire-sr with `TLS=1 HTTP2=1 PORT=8443` and **leave `PUBLIC_BASE_URL` unset** (default `https://api.game-idolypride.jp`), so master download URLs keep the game hostname. Setting it to an IP causes "Curl error 60 … Common Name does not match".
6. Switch off = official servers: no redirect hooks are installed, and the cached CA is deleted.

## In-game server selection

One build covers the official server and any number of private sumire-sr servers, and players
pick the server inside the game. The module app is not required: this works in standalone mode
(LSPatch-embedded module, app not installed).

**Servers page (module app).** The module app's *Servers* page is only an add-server shortcut:
URLs entered there are saved as `suggestedServerUrls` in `ipr-config.json`, forwarded by
`initIprConfig` to `<game dataDir>/files/hoshimi-profiles/suggested.json` (main process only), and
listed in the picker as `<url> (from app)` unless a profile with the same normalized URL already
exists. Choosing one runs the normal add-server flow (CA bootstrap, fingerprint confirmation,
switch warning); the page never enables a private server and never changes the active one. On the
first app start after upgrading, an old `privateServerUrl` is moved into the suggested list and
the legacy `privateServerEnabled` / `privateServerUrl` / `privateServerCaPem` fields are cleared.

- **Switch server button.** `ServerSwitchOverlay.kt` adds a small native `Button` to the game
  activity's content view. Native hooks on `Solis.Title.TitlePresenter` (`Start`,
  `MoveOutGameAsync`, `OnDestroy` in `Hook.cpp`) report title-screen visibility through
  `HoshimiHookMain.onTitleScreenChanged`, so the button appears as soon as the title presenter
  starts even when the text probe is not active yet. The older screen-root probe
  (`ProbeTextComponent` -> `HoshimiHookMain.onScreenRootChanged`, visible while the root contains
  `TITLE_SCREEN_ROOT_MARKER` (`Title`)) stays as a fallback. Missing TitlePresenter methods only
  log a warning.
- **Picker.** `ServerPromptDialog.kt` builds a plain `AlertDialog` in code (no layout
  resources): "Official server", every saved private profile, and "Add private server…". It is
  shown once configuration resolution finished (the module app answered or the standalone
  fallback ran) when no server has been chosen yet, and from the switch button.
- **Adding a server.** The address may be `host:port`, `https://host[:port]` or
  `http://host[:port]`, optionally with `#sha256=<fingerprint>`. A missing scheme means https and
  a missing port is the scheme default. The CA is bootstrapped from
  `<url>/.well-known/sumire/ca.pem`: a certificate chain the system already trusts is accepted
  silently; an untrusted (self-signed) instance is fetched once with a trust-all connection for
  the bootstrap request only, the returned CA must have signed the presented leaf certificate,
  and the player confirms the CA fingerprint unless `#sha256=` matched. Plain `http://` always
  requires the confirmation.
- **Switching clears the local account.** Each server has its own login and the refresh token is
  bound to the server, so a switch wipes the account files instead of swapping them. The player
  confirms a warning first (the picker's confirmation dialog); then `ServerProfileStore.kt`
  writes `active.json`, writes a `clear-pending` marker, and asks native code to run the game's
  own Delete Data routine (`Solis.Common.SolisInitializer.ClearUserData`), invoked on the Unity
  main thread from the `EndCameraRendering` hook. The process is relaunched after the call
  completes or after a 3 s timeout. If the native call never ran, the next start deletes the
  live account files before Firebase's ContentProvider runs (main process only):
  `shared_prefs/com.google.firebase.auth.api.Store.*.xml`,
  `shared_prefs/game.qualiarts.idolypride.v2.playerprefs.xml` and `files/octo/user/`. Asset and
  master caches under `files/octo/v1` and `files/octo/pdb` stay shared. Accounts must be linked
  (data link / account transfer) to log in again after a switch; the account itself is not
  deleted from the server. Old `<profileId>/account*` stash directories are left untouched, and
  a legacy `pending.json` is still finished or aborted on start.

Files under `<game dataDir>/files/hoshimi-profiles/` (managed by `ServerProfileStore.kt`):

| File | Contents |
|---|---|
| `profiles.json` | `{id, kind: "official"\|"private", url, caPem, caSha256, label}`; `official` always exists |
| `active.json` | `{activeId}` |
| `suggested.json` | JSON array of app-suggested server URLs; picker shows them as "from app" until added |
| `clear-pending` | target profile id, written before a switch and consumed on the next start |
| `pending.json` | legacy swap journal `{targetId, fromId, phase, attempts}`; only read now |
| `<profileId>/account/` | legacy per-server stash, no longer written |

A private profile id is `private-` plus the first 8 hex chars of the SHA-1 of the normalized URL
(lowercase scheme and host, no trailing slash).

Precedence:

1. An `iprData` config from the module app with **private server enabled and a URL** wins; that is
   how the existing sumire-sr dev setup keeps working. It is also mirrored into a
   `private-…` profile. While it is in charge, the switch button shows "Server is managed by the
   HoshimiLocalify app" instead of the picker.
2. Otherwise the active profile decides: `official` disables the private server, `private`
   enables it with that profile's URL and CA. An app config with private server off does not
   disarm an active private profile.
3. With no `active.json` (first launch), a legacy cached CA at `files/hoshimi-private-server-ca.pem`
   is migrated into a profile, otherwise the official profile is created and the picker is shown.

The CA cache keeps a `# source=profile|app` marker so a CA derived from an in-game profile is
dropped when the active profile becomes official, while an app-supplied CA behaves as before.
A private server may be an IPv4 literal or a hostname (public instance): the Java redirect
resolves the hostname through the original resolver and `PrivateServer.cpp` resolves it once in
`Install()` (before its own `getaddrinfo` hook exists), caching the address.

## Status

| Piece | State |
|---|---|
| Redirect (gRPC, master downloads, Octo) with the system CA via Magisk | verified on the Pixel 6 (rooted, LSPosed), 6.0.3 |
| Without the system CA (Java trust hook) | verified on the Pixel. Octo returned 200, and the game reached Home as an existing account |
| Toggle off → official servers | verified. Connections went to the official API (35.221.155.103) and climaster; the cached CA was deleted |
| Unrooted LSPatch over Wi-Fi with no tunnel | verified on a Moto G Play 2024 (Android 14). The module loaded, and redirect + trust reached the server |
| New-player sign-up (Auth:Create + Firebase redirect) | implemented in sumire-sr PR #6 and in this fork's Firebase redirect. See sumire-sr `docs/SOLIS_INTEROP.md` / PR #6 for the current state |
| Known gaps | the stale-CA window on the first home-screen launch after disabling; issuer-list visibility is process-wide |

