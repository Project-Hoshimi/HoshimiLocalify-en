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
| Server URL | Scheme + host + port, e.g. `https://sumire.lan:8443`, no trailing slash |
| Server CA PEM | PEM of the private server's CA (one or more certificates) |

When enabled, the mod:

1. rewrites `Solis.Common.Network.Api.GetHost()` to the configured URL (gRPC API);
2. prepends the configured CA to `Api.GetSSLRootCertificates()` so YAHA/rustls trusts it;
3. rewrites the scheme+authority of `OctoSettings.url` (asset catalog) to the configured URL;
4. (Phase 2, rootless) rewrites `UnityWebRequest` URLs for the game/Octo hosts and validates
   the server certificate against the configured CA.

The Frida path (`sumire-sr/frida/e2e_hooks.js`) remains the supported fallback.
