## 1.0.0 (unreleased)

- Fork of capacitor-secure-storage-plugin 0.13.0 maintained by Skip Pay
- Package renamed to `better-capacitor-secure-storage-plugin` (`npm install better-capacitor-secure-storage-plugin`), the plugin name `SecureStoragePlugin` and the JavaScript API are unchanged
- Capacitor >= 8.3.0 only, iOS 15+, Android minSdk 24
- iOS: encryption of stored values with a Secure Enclave key, on by default (`encryptValues` plugin option, set `false` to opt out)
- iOS: configurable keychain accessibility class (`accessibility` plugin option, default `whenUnlockedThisDeviceOnly`, `afterFirstUnlock` available as an explicit opt-out) and per-call `accessibility` option on `set` (upstream issue #151)
- iOS: the plugin queues calls made while the device is locked and runs them in order after unlock instead of failing them as missing keys. It tracks protected data from UIKit notifications without blocking on the main thread, and a one-second timer retries waiting calls so a missed notification cannot strand them
- iOS: new items live in the keychain service `cap_sec_v2` in the app-private access group `<team id>.<bundle id>`, resolved at runtime, with a logged fallback to the default group when the app may not use it. The Secure Enclave key is created there too. Items of upstream versions stay in `cap_sec` and in the bundle id service as legacy items
- iOS: `get` reads `cap_sec_v2` first. A key without a `cap_sec_v2` item is read from its legacy copies across groups plus the bundle id service copy: a `cap_sec` copy written by an earlier build of this fork wins, otherwise the copy the 0.13.0 query returns, so the first read after the upgrade returns the value the app has been using. The plugin copies that value into `cap_sec_v2` with the tightened class and current encoding, reads it back and verifies it, and deletes the new item again when it does not verify. `get` copies its key in the call. A sweep copies every `cap_sec` key without a `cap_sec_v2` item once per launch in the foreground, whatever `encryptValues` says, and for keys that have one it only reads the listings. It starts once about 1.5 seconds passed after a completed app call without another one (or about five seconds after load without a call), so it never runs between two calls the app makes in a row. A copy that an earlier build of this fork wrote is tightened the same way
- iOS: the migration runs in two phases. Phase 1, this release: the migration never modifies a legacy item in `cap_sec`, in any access group, or in the bundle id service. It does not delete, re-encrypt, re-class or relabel them, and `set` writes only `cap_sec_v2`. Phase 2: deleting every legacy copy after a verified `cap_sec_v2` write, and in the sweep for keys that already have their `cap_sec_v2` item, is implemented and tested but stays off (`deletesLegacyCopies` in `SecureStorageVault.swift`) until a later release switches it on. An explicit `remove` or `clear` deletes legacy copies in both phases, as upstream 0.13.0 did, so a removed value cannot come back: `remove` deletes the `cap_sec_v2` item and every legacy copy of the key, and `clear` deletes `cap_sec_v2`, `cap_sec` and the bundle id copies of the keys found there. Both delete the legacy items first and `cap_sec_v2` last, and keep `cap_sec_v2` and reject when a legacy deletion fails, so a later `get` never returns an older value. `keys` lists the keys of `cap_sec_v2` and `cap_sec`, each once
- iOS: the Secure Enclave key class follows the configured class: `whenUnlockedThisDeviceOnly`, or `afterFirstUnlockThisDeviceOnly` for an after-first-unlock configuration. Decryption never creates a key and `clear` never deletes it
- iOS: an item that cannot be decrypted rejects with `Item with given key does not exist` and code `UNREADABLE` and stays overwritable. The fork-only message `Item with given key could not be decrypted` is gone
- iOS: a decryption that fails on an unlocked device is retried twice with a fresh key lookup (about 50 ms and 200 ms apart). Only `errSecParam` or `errSecDecode` after the retries, a key that does not exist, a prefix without ciphertext and non-UTF-8 plaintext are final (`UNREADABLE`). Every other failure, a failed key lookup included, waits like a locked device. A waiting call makes a single attempt per timer tick without the retry delays. If the failure never recovers, the key becomes unusable for the process (below), or, when the key still opens fresh ciphertext, the call ends through the lost-item escape
- iOS: an item the keychain keeps refusing with -25308 on an unlocked device, as after a Quick Start migration, counts as lost after three timer retries confirmed by a throwaway write that is not refused with `errSecInteractionNotAllowed`: `get` rejects as missing with code `UNREADABLE`, `remove` and `clear` resolve unless a deletion fails with an error other than -25308, then they reject with code `STORAGE_ERROR`, `set` replaces it
- iOS: a Secure Enclave key whose lookup or decryption keeps returning -25308 on an unlocked device, or keeps failing there for a reason not known to be permanent (a decryption only while the key cannot open fresh ciphertext either), is unusable for the rest of the process after the same three confirmed retries: `set` stores plaintext with the strict class, ciphertext reads as `UNREADABLE` right away, `keyBackend` reports `unusable`. The plugin never deletes the key
- iOS: when encryption fails for a reason other than a locked device, or the new ciphertext does not decrypt in the check before the write, `set` stores plaintext with at least `whenUnlockedThisDeviceOnly` instead of rejecting, see When encryption is not available in the README. A `cap_sec_v2` copy whose read-back does not verify is deleted again. A plaintext `cap_sec_v2` item is encrypted in place by its next `get` once encryption works
- iOS: when the winning legacy copy of a key cannot be decrypted, nothing is copied and no other copy is promoted or rewritten. A `cap_sec_v2` item that cannot be decrypted never falls back to a legacy copy
- iOS: `getDiagnostics()` adds `decryptRetries`, `conflictingDuplicates` and `legacyCopiesKept` (keys that have their `cap_sec_v2` item while legacy copies are still stored), optional in the TypeScript type because Android does not report them. `keyBackend` gains `unusable` (iOS), `keystoreAes` and `keystoreRsaLegacy` (Android), `accessGroupMode` gains `n/a` (Android)
- iOS: `clear` removes a bundle id service copy only for a key that also exists in `cap_sec_v2` or `cap_sec`. Apps that need a hard wipe also call `remove` for the keys they know
- iOS: rejections carry a `code` (`NOT_FOUND`, `UNREADABLE`, `UNSUPPORTED_ACCESSIBILITY`, `STORAGE_ERROR`, `LOCKED` reserved), the messages are unchanged
- `getDiagnostics()` returns counters, the key backend and the access group mode on iOS and Android. Web resolves zeros
- iOS: the SwiftKeychainWrapper dependency is gone. The plugin accesses the keychain directly through Security.framework
- Android and web: `accessibility` is accepted and ignored
- Android: values are encrypted with an AES-256-GCM AndroidKeyStore key (alias `<packageName>_cap_sec_aes_v2`) and stored as `v2:` + base64(IV, ciphertext, tag), with the storage key as additional authenticated data
- Android: upstream RSA entries and plaintext base64 entries are still read and are copied in the new format into the separate SharedPreferences file `cap_sec_v2` on read and in a background pass on first use. The plugin keeps the RSA key for that and never generates a new RSA key
- Android: two-phase migration. In this release the migration never modifies the entries in `cap_sec` or the RSA key, reads prefer `cap_sec_v2` and `set` writes there only. Deleting the `cap_sec` entries after a verified copy, and the RSA key and the `cap_sec` file once it is empty, is implemented and tested but switched off (`DELETE_LEGACY_STORAGE` in `SecureStore.java`) until a later release switches it on. An explicit `remove` or `clear` deletes from both files in both phases, as upstream did, so a removed value cannot come back. Both delete from `cap_sec` first and `cap_sec_v2` last. When the `cap_sec` deletion fails they keep `cap_sec_v2`, and when any deletion fails they reject with code `STORAGE_ERROR`, message `Remove failed` for `remove` and `error` for `clear`. `getDiagnostics()` adds the Android-only field `legacyEntriesKept`, keys whose `cap_sec` entry is still stored after its migration
- Android: a migrated entry is written only after the new blob decrypted back to the same bytes, and only once an AES round-trip self-test passed in the process. Otherwise the older entry stays and keeps being read, and the key is counted in the Android-only diagnostics field `migrationSkipped`, legacy entries still stored whose migration was skipped
- Android: an older entry with characters outside the base64 alphabet, or one that decodes to nothing, is unreadable instead of being read as a shorter value or `""`
- Android: `set` rejects with `error` / code `STORAGE_ERROR` when the value cannot be encrypted or its ciphertext does not decrypt back to the same bytes, instead of silently storing nothing. Keystore errors are retried and never latched for the process. On the AES path only a wrong GCM tag and a missing key are permanent, `IllegalBlockSizeException` and `BadPaddingException` are retried and end as `UNREADABLE` / `decryptFailures`, not `lostItems`. On the legacy RSA path `IllegalBlockSizeException` is retried the same way unless the stored bytes are valid UTF-8 and can still be read as plaintext. On Android 13+ a `KeyStoreException` cause reporting `isTransientFailure()` is always retried
- Android: after an AES encrypt failed on all attempts, migrations and the background pass make a single keystore attempt without retry delays until the next AES operation succeeds, so a broken keystore does not add about 250 ms to every read of an older entry. An older entry the background pass cannot read in that single attempt is not counted in `decryptFailures` unless the failure is permanent. `set` keeps its retries
- Android: `get` rejects with code `NOT_FOUND` for a missing key and `UNREADABLE` for an entry that cannot be decrypted, the message stays `Item with given key does not exist`. `remove` deletes an unreadable entry instead of reporting it missing
- Android: `getDiagnostics()` with migration and failure counters
- Android: no keystore work in `load()`, storage calls run in order on one plugin thread per process shared by all plugin instances. The API < 23 code and the SDK16/SDK18 split are removed
- Android: older builds do not read `cap_sec_v2`. While `cap_sec` is kept, a downgrade finds the values as they were before the upgrade, without later writes and without keys removed or cleared since
- `KeychainAccessibility`, `SecureStorageSetOptions`, `SecureStorageDiagnostics` and `SecureStorageErrorCode` types exported, `PluginsConfig` of `@capacitor/cli` augmented with `SecureStoragePlugin`
- iOS: older builds do not read `cap_sec_v2`. While the legacy items are kept, a downgrade finds the values as they were before the upgrade, without later writes and without keys removed or cleared since, see the README

- Behaviour change versus upstream on iOS: with the defaults, values are not readable while the device is locked and calls wait until unlock. Apps that must read values in that state set `accessibility` to `afterFirstUnlock`
- Behaviour change versus upstream on iOS: with the defaults (`whenUnlockedThisDeviceOnly` and a Secure Enclave key), values no longer move to a new iPhone through a backup restore or Quick Start, and an erase-and-restore of the same device loses them, because the Secure Enclave key does not survive it. The app sees missing keys
- Behaviour change versus upstream on Android: writes fail closed. On a device whose AndroidKeyStore cannot create or use the AES key, `set` rejects with `error` / code `STORAGE_ERROR` where upstream stored the value as plaintext base64. Reads of existing entries are not affected. See When encryption is not available in the README

## Upstream history (capacitor-secure-storage-plugin)

## v0.13.0

- migrate to capacitor 8.0

## v0.12.0

- add support for SPM

## v0.11.0

- migrate to capacitor 7.0

## v0.10.0

- migrate to capacitor 6.0

## v0.9.0

- migrate to capacitor 5.0

## v0.8.1

- iOS - calling clear if storage if empty is not throwing an error

## v0.8.0

- migrate to capacitor 4.0
- for Capacitor 3.X.X install version v0.7.1
  - `npm install capacitor-secure-storage-plugin@0.7.1`

## v0.7.1

- iOS - access when a device is locked, but after first unlock of device

## v0.7.0

- based on current Capacitor 3.5.1 plugin template
- iOS - access when a device is locked
- fixed keys() on Web

## v0.6.2

- fix keys() serialization error on Android

## v0.6.1

- fix keys() serializable error on iOS

## v0.6.0

- migrate to capacitor 3.0
- for Capacitor 2.X.X install version v0.5.1
  - `npm install capacitor-secure-storage-plugin@0.5.1`

- import plugin in web project in Capacitor v3 is `import { SecureStoragePlugin } from 'capacitor-secure-storage-plugin';` directly, instead of import of Plugins from capacitor/cor

  e

## v0.5.1

- fix Capacitor version to 2.X.X

## v0.5.0

- added keys() method - warning: returns just keys saved from this version up
- iOS: instead on standard keychain, wrapper service is used
- migration is not needed, plugin saves new values to wrapped keychain and get method uses standard keychain as a fallback

## v0.4.0

- rebased on Capacitor v2 plugin template
- added getPlatform() method

## v0.3.2

- update Capacitor dependencies

## v0.3.1

- fix long string handling
