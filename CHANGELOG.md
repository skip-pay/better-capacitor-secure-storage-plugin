## 1.0.0 (unreleased)

- Fork of capacitor-secure-storage-plugin 0.13.0 maintained by Skip Pay
- Package renamed to `better-capacitor-secure-storage-plugin` (`npm install better-capacitor-secure-storage-plugin`), the plugin name `SecureStoragePlugin` and the JavaScript API are unchanged
- Capacitor >= 8.3.0 only, iOS 15+, Android minSdk 24
- iOS - encryption of stored values with a Secure Enclave key, on by default (`encryptValues` plugin option, set `false` to opt out)
- iOS - configurable keychain accessibility class (`accessibility` plugin option, default `whenUnlockedThisDeviceOnly`, `afterFirstUnlock` available as an explicit opt-out) and per-call `accessibility` option on `set` (upstream issue #151)
- iOS - calls made while the device is locked are queued in order and run after unlock instead of failing as missing keys. Protected data is tracked from UIKit notifications without blocking on the main thread, and a one-second timer retries waiting calls so a missed notification cannot strand them
- iOS - items live in the app-private access group `<team id>.<bundle id>`, resolved at runtime, with a logged fallback to the default group when the app may not use it. The Secure Enclave key is created there too
- iOS - every key is settled by one migration unit: all copies across groups plus the bundle id service copy, the newest `cap_sec` copy wins, it is written into the app-private group with the tightened class and current encoding, read back and verified, and only then are the other copies deleted. `get` settles its key in the call, a sweep settles all keys once per launch in the foreground, whatever `encryptValues` says. A class chosen by `set` survives the sweep
- iOS - the Secure Enclave key class follows the configured class: `whenUnlockedThisDeviceOnly`, or `afterFirstUnlockThisDeviceOnly` for an after-first-unlock configuration. Decryption never creates a key and `clear` never deletes it
- iOS - an item that cannot be decrypted rejects with `Item with given key does not exist` and code `UNREADABLE` and stays overwritable. The fork-only message `Item with given key could not be decrypted` is gone
- iOS - an item the keychain keeps refusing with -25308 on an unlocked device, as after a Quick Start migration, is classified as lost after three timer retries confirmed by a throwaway write: `get` rejects as missing with code `UNREADABLE`, `remove` and `clear` resolve, `set` replaces it
- iOS - when encryption fails for a reason other than a locked device, `set` stores plaintext with at least `whenUnlockedThisDeviceOnly` instead of rejecting
- iOS - rejections carry a `code` (`NOT_FOUND`, `UNREADABLE`, `UNSUPPORTED_ACCESSIBILITY`, `STORAGE_ERROR`, `LOCKED` reserved), the messages are unchanged
- `getDiagnostics()` returns counters, the key backend and the access group mode on iOS and Android. Web resolves zeros
- iOS - remove the SwiftKeychainWrapper dependency, the keychain is accessed directly through Security.framework
- Android and web - `accessibility` is accepted and ignored
- Android - values are encrypted with an AES-256-GCM AndroidKeyStore key (alias `<packageName>_cap_sec_aes_v2`) and stored as `v2:` + base64(IV, ciphertext, tag), with the storage key as additional authenticated data
- Android - upstream RSA entries and plaintext base64 entries are still read and are rewritten in the new format on read and in a background pass on first use. The RSA key is kept for that, no new RSA key is ever generated
- Android - `set` rejects with `error` / code `STORAGE_ERROR` when the value cannot be encrypted, instead of silently storing nothing or falling back to plaintext. Keystore errors are retried and never latched for the process
- Android - after an AES encrypt failed on all attempts, migrations and the background pass make a single keystore attempt without retry delays until the next AES operation succeeds, so a broken keystore does not add about 250 ms to every read of an older entry. `set` keeps its retries
- Android - `get` rejects with code `NOT_FOUND` for a missing key and `UNREADABLE` for an entry that cannot be decrypted, the message stays `Item with given key does not exist`. `remove` deletes an unreadable entry instead of reporting it missing
- Android - `getDiagnostics()` with migration and failure counters
- Android - no keystore work in `load()`, storage calls run in order on a plugin thread. The API < 23 code and the SDK16/SDK18 split are removed
- Android - do not downgrade after values were written or migrated, older builds cannot read the `v2:` format
- `KeychainAccessibility`, `SecureStorageSetOptions`, `SecureStorageDiagnostics` and `SecureStorageErrorCode` types exported, `PluginsConfig` of `@capacitor/cli` augmented with `SecureStoragePlugin`
- Do not downgrade to a build without this fork after values were written with encryption on, see the README
- CI runs the Android unit tests, the Java prettier check and the iOS keychain harness on a simulator. A `v*` tag publishes to npm with trusted publishing and provenance, see Releasing in the README

- Behaviour change versus upstream on iOS: with the defaults, values are not readable while the device is locked and calls wait until unlock. Apps that must read values in that state set `accessibility` to `afterFirstUnlock`
- Accepted exception on Android to the no-user-visible-change rule, by product owner decision: writes stay fail-closed. Only on devices whose AndroidKeyStore cannot create or use the AES key, `set` rejects with `error` / code `STORAGE_ERROR` where upstream stored the value as plaintext base64. Reads of existing entries are not affected

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
