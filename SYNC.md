# Syncing from the private fork

The private fork is the source of truth. To publish a code update:

1. In the private fork, finish the change, commit, and push to `main`.
2. Re-snapshot into `~/HoshimiLocalify-en-public` (exclude `.git`, `app/build`, `build`,
   `.gradle`, `.kotlin`, `.idea`, `local.properties`, and `app/src/main/assets/hoshimi-local`).
3. Delete `.gitmodules`, `update_submodule.bat`, and `app/src/main/assets/hoshimi-local`.
4. Bump `versionName` in `app/build.gradle`, commit, and push to `main`.
5. The build workflow runs `./gradlew clean assembleRelease` and uploads both flavors onto
   the new tag.

The data payload is not stored here: the build workflow downloads the latest
`tokanada/ipr-translation-data-en` release before building. Each data release produces its own GitHub release tagged `<versionName>-data.<data tag>` (newest 7 kept).
