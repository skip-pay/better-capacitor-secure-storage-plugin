[![npm version](https://badge.fury.io/js/better-capacitor-secure-storage-plugin.svg)](https://badge.fury.io/js/better-capacitor-secure-storage-plugin)

# better-capacitor-secure-storage-plugin

Capacitor plugin for storing string values securely on iOS and Android.

## Fork notice

This is a Skip Pay fork of [martinkasa/capacitor-secure-storage-plugin](https://github.com/martinkasa/capacitor-secure-storage-plugin), created to harden the Keychain/Keystore configuration. It keeps the same JavaScript API and the plugin name `SecureStoragePlugin`, so switching from upstream is an import change.

What differs from upstream:

- iOS values can be encrypted at rest with a Secure Enclave key (`encryptValues`, on by default).
- The iOS keychain accessibility class is configurable, globally in the plugin configuration and per `set` call (upstream issue [#151](https://github.com/martinkasa/capacitor-secure-storage-plugin/issues/151)). The default is the hardened `whenUnlockedThisDeviceOnly`, `afterFirstUnlock` stays available as an explicit opt-out.
- iOS no longer fails a read as "missing" while the device is locked. The plugin queues calls that hit a locked keychain and runs them in order after unlock.
- The SwiftKeychainWrapper dependency is gone. iOS talks to the keychain directly through Security.framework.
- iOS items live in the app-private keychain access group `<team id>.<bundle id>`, not in whatever group the app's entitlements make the default (often a group shared with extensions).
- iOS writes into the new keychain service `cap_sec_v2`. The plugin copies existing items from `cap_sec` and the bundle id service into it once per launch and on first read, encrypted and with at least the configured class, taking the value upstream 0.13.0 read. In this release the older items stay exactly as they were, so a downgrade still finds them. A later app version deletes them, see Migration under iOS.
- iOS rejections carry a `code` in addition to the unchanged messages, and `getDiagnostics()` reports what the plugin did.
- Android encrypts with AES-256-GCM in AndroidKeyStore instead of chunked RSA, copies RSA and plaintext entries from `cap_sec` into the new file `cap_sec_v2`, and rejects a write it cannot encrypt instead of storing it in plaintext.
- Both platforms migrate in two phases. This release writes the new copy and keeps the older storage on the device, so a rollback still finds it. The deletion of the older storage is implemented and tested but switched off by a constant marked with a TODO for SS-12183 (`SecureStorageVault.deletesLegacyCopies` on iOS, `SecureStore.DELETE_LEGACY_STORAGE` on Android). The app version that follows, once most users have migrated, switches it on.

The iOS defaults are hardened. The plugin encrypts values with a Secure Enclave key and stores them with the `whenUnlockedThisDeviceOnly` class, so they are not available while the device is locked and do not leave the device in backups. Setting `encryptValues` to `false` and `accessibility` to `afterFirstUnlock` gives the upstream storage format and class. New items still go to `cap_sec_v2` in the app-private access group. On Android the plugin encrypts values with an AES-256-GCM AndroidKeyStore key and copies older entries into `cap_sec_v2` on read while the older file stays, see Android below. Web behaves as in upstream 0.13.0.

Requirements: Capacitor >= 8.3.0, iOS 15+, Android minSdk 24. For older Capacitor versions use the upstream package.

## How to install

```bash
npm install better-capacitor-secure-storage-plugin
npx cap sync
```

## Usage

In a component where you want to use this plugin add to or modify imports:

```ts
import { SecureStoragePlugin } from 'better-capacitor-secure-storage-plugin';
```

## Configuration

Set the options under `plugins.SecureStoragePlugin` in the Capacitor configuration.

<docgen-config>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

Configuration of better-capacitor-secure-storage-plugin.

| Prop                | Type                                                                    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Default                                   | Since |
| ------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ----- |
| **`accessibility`** | <code><a href="#keychainaccessibility">KeychainAccessibility</a></code> | Default keychain accessibility class for items written by the plugin (iOS only). `afterFirstUnlock` is available as an explicit opt-out, for example when the app must read values while the device is locked. A legacy item copied into `cap_sec_v2` gets this class or its own, whichever is stricter. An unknown value makes every storage call reject with `Unsupported accessibility value in plugin configuration`. Only `getPlatform` still resolves.                                                                                                                                                                                                                                                                                                                                                                                | <code>'whenUnlockedThisDeviceOnly'</code> | 1.0.0 |
| **`encryptValues`** | <code>boolean</code>                                                    | Encrypt stored values with a Secure Enclave key (iOS only). Enabled by default. Set `false` to opt out. The plugin writes into the keychain service `cap_sec_v2`. Items of upstream versions in `cap_sec` are copied into it, encrypted, by the first `get` of a key and by a sweep once per app launch, in the foreground, after about 1.5 s without app calls once the first call has completed (or about five seconds after load when the app makes no call). Items in the app bundle id service are copied when `get` reads them. The items in `cap_sec` and the bundle id service stay as they were until the deletion of older copies is switched on (SS-12183). A `cap_sec_v2` item that holds plaintext is encrypted by its next `get` once encryption works. Android always encrypts with AndroidKeyStore, web ignores the option. | <code>true</code>                         | 1.0.0 |

### Examples

In `capacitor.config.json`:

```json
{
  "plugins": {
    "SecureStoragePlugin": {
      "accessibility": "afterFirstUnlock",
      "encryptValues": false
    }
  }
}
```

In `capacitor.config.ts`:

```ts
/// <reference types="better-capacitor-secure-storage-plugin" />

import { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  plugins: {
    SecureStoragePlugin: {
      accessibility: "afterFirstUnlock",
      encryptValues: false,
    },
  },
};

export default config;
```

</docgen-config>

An unknown `accessibility` value in the configuration makes every storage call reject with `Unsupported accessibility value in plugin configuration`. `getPlatform` still resolves. A value of the wrong type is not detected and falls back to the default: `encryptValues` must be a boolean (the string `"false"` counts as `true`) and `accessibility` must be a string.

### Accessibility

| Value                            | iOS constant                                       | Available                              |
| -------------------------------- | -------------------------------------------------- | -------------------------------------- |
| `whenUnlocked`                   | `kSecAttrAccessibleWhenUnlocked`                   | only while the device is unlocked      |
| `whenUnlockedThisDeviceOnly` (default) | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` | only while unlocked, not in backups |
| `afterFirstUnlock`               | `kSecAttrAccessibleAfterFirstUnlock`               | after the first unlock since boot      |
| `afterFirstUnlockThisDeviceOnly` | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | after first unlock, not in backups     |
| `whenPasscodeSetThisDeviceOnly`  | `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`  | while unlocked, only with a passcode   |

Every write applies the class. A per-call `accessibility` on `set` wins over the configured default and stays on the item until the next `set`. The migration described under Migration below gives a value it copies from upstream or an older build at least the configured class. It never loosens a class. Changing the configured class later affects new writes only. Android and web accept `accessibility` and ignore it, because Android already encrypts values with AndroidKeyStore and the browser has no keychain. `encryptValues` is iOS only.

## API

<docgen-index>

* [`get(...)`](#get)
* [`set(...)`](#set)
* [`remove(...)`](#remove)
* [`clear()`](#clear)
* [`keys()`](#keys)
* [`getPlatform()`](#getplatform)
* [`getDiagnostics()`](#getdiagnostics)
* [Interfaces](#interfaces)
* [Type Aliases](#type-aliases)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### get(...)

```typescript
get(options: { key: string; }) => Promise<{ value: string; }>
```

Read a stored value.

| Param         | Type                          | Description      |
| ------------- | ----------------------------- | ---------------- |
| **`options`** | <code>{ key: string; }</code> | The key to read. |

**Returns:** <code>Promise&lt;{ value: string; }&gt;</code>

--------------------


### set(...)

```typescript
set(options: SecureStorageSetOptions) => Promise<{ value: boolean; }>
```

Store a value under a key, replacing an existing one.

| Param         | Type                                                                        | Description                                                             |
| ------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **`options`** | <code><a href="#securestoragesetoptions">SecureStorageSetOptions</a></code> | The key, the value and optionally the iOS keychain accessibility class. |

**Returns:** <code>Promise&lt;{ value: boolean; }&gt;</code>

--------------------


### remove(...)

```typescript
remove(options: { key: string; }) => Promise<{ value: boolean; }>
```

Remove a stored value.
On iOS it deletes the `cap_sec_v2` item and every legacy copy of the key, in `cap_sec` in any access group and in the
bundle id service.

| Param         | Type                          | Description        |
| ------------- | ----------------------------- | ------------------ |
| **`options`** | <code>{ key: string; }</code> | The key to remove. |

**Returns:** <code>Promise&lt;{ value: boolean; }&gt;</code>

--------------------


### clear()

```typescript
clear() => Promise<{ value: boolean; }>
```

Remove all values in the plugin's keychain services plus the legacy bundle id copies of those keys.
On iOS it deletes every item in `cap_sec_v2` and `cap_sec`, in any access group. A bundle id copy is removed only for a
key that also exists in one of those services. Legacy items left only in the bundle id service are kept and `get` can
still return them, so an app that needs a hard wipe also calls `remove` for each key it knows.

**Returns:** <code>Promise&lt;{ value: boolean; }&gt;</code>

--------------------


### keys()

```typescript
keys() => Promise<{ value: string[]; }>
```

List the keys of all values in the plugin's keychain services.
On iOS the keys of `cap_sec_v2` and of the legacy `cap_sec` service, each once. Legacy items in the bundle id service are
not listed until `get` copied them.

**Returns:** <code>Promise&lt;{ value: string[]; }&gt;</code>

--------------------


### getPlatform()

```typescript
getPlatform() => Promise<{ value: string; }>
```

Get the implementation in use.

**Returns:** <code>Promise&lt;{ value: string; }&gt;</code>

--------------------


### getDiagnostics()

```typescript
getDiagnostics() => Promise<SecureStorageDiagnostics>
```

Read counters and the key and access group state of the native storage, for support and monitoring.
Resolves right away, also while other calls wait for the device to unlock.
Web resolves zeros with `keyBackend: 'none'` and `accessGroupMode: 'default'`. Android resolves real `migrated`,
`lostItems` and `decryptFailures` counters and `keyBackend` `keystoreAes`, `keystoreRsaLegacy` or `none`, while
`parked`, `duplicatesResolved` and `plaintextFallbacks` are always `0` and `accessGroupMode` is `n/a`.

**Returns:** <code>Promise&lt;<a href="#securestoragediagnostics">SecureStorageDiagnostics</a>&gt;</code>

**Since:** 1.0.0

--------------------


### Interfaces


#### SecureStorageSetOptions

| Prop                | Type                                                                    | Description                                                                                                                                                                                                           | Since |
| ------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| **`key`**           | <code>string</code>                                                     | Key under which the value is stored.                                                                                                                                                                                  |       |
| **`value`**         | <code>string</code>                                                     | Value to store.                                                                                                                                                                                                       |       |
| **`accessibility`** | <code><a href="#keychainaccessibility">KeychainAccessibility</a></code> | Keychain accessibility class for this item (iOS only). Overrides the `accessibility` plugin configuration for this call. An unknown value rejects with `Unsupported accessibility value`. Ignored on Android and web. | 1.0.0 |


#### SecureStorageDiagnostics

State of the native storage for support and monitoring. Counters start at zero when the app process starts.
On Android `parked`, `duplicatesResolved` and `plaintextFallbacks` are always `0` and `accessGroupMode` is `n/a`.

| Prop                        | Type                                                                                                       | Description                                                                                                                                                                                                                                                                                                                                                                               | Since |
| --------------------------- | ---------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| **`parked`**                | <code>number</code>                                                                                        | Calls that had to wait for protected data, for example because the device was locked. Always `0` on Android.                                                                                                                                                                                                                                                                              |       |
| **`migrated`**              | <code>number</code>                                                                                        | On iOS keys copied from the legacy keychain service `cap_sec` or the bundle id service into `cap_sec_v2` and verified by a read-back. On Android entries rewritten from RSA or plaintext to AES-GCM.                                                                                                                                                                                      |       |
| **`duplicatesResolved`**    | <code>number</code>                                                                                        | Legacy copies deleted once their key had a verified `cap_sec_v2` item: `cap_sec` items in any access group and bundle id service items. Stays `0` until the deletion of older copies is switched on. Always `0` on Android.                                                                                                                                                               |       |
| **`lostItems`**             | <code>number</code>                                                                                        | Calls whose item kept reporting a locked keychain while the device was unlocked and that were completed as if the item were missing. On Android distinct keys whose entry is intact but does not decrypt.                                                                                                                                                                                 |       |
| **`decryptFailures`**       | <code>number</code>                                                                                        | Reads of an item that could not be decrypted or decoded. On Android distinct keys in an unknown format or failing after all retries.                                                                                                                                                                                                                                                      |       |
| **`plaintextFallbacks`**    | <code>number</code>                                                                                        | Values stored as plaintext with the strict class because encryption was unavailable. Always `0` on Android, which rejects such a write instead.                                                                                                                                                                                                                                           |       |
| **`decryptRetries`**        | <code>number</code>                                                                                        | Decryption attempts repeated after a failure on an unlocked device, with the key looked up again (iOS, web resolves `0`). Optional because Android does not report it.                                                                                                                                                                                                                    | 1.0.0 |
| **`conflictingDuplicates`** | <code>number</code>                                                                                        | Legacy copies whose value differed from the copy that won when their key was copied into `cap_sec_v2` (iOS, web resolves `0`). Optional because Android does not report it.                                                                                                                                                                                                               | 1.0.0 |
| **`legacyCopiesKept`**      | <code>number</code>                                                                                        | Keys that have their `cap_sec_v2` item while legacy copies (`cap_sec` in any access group or the bundle id service) are still stored, because the deletion of older copies is not switched on yet or a delete failed. Each key counts once per process (iOS, web resolves `0`). Optional because Android does not report it.                                                              | 1.0.0 |
| **`migrationSkipped`**      | <code>number</code>                                                                                        | Android only: legacy entries still stored whose migration was skipped because the re-encrypted value did not decrypt back to the same bytes, could not be encrypted, or could not be written. A key leaves the count once a later migration or `set` wrote its `cap_sec_v2` entry, or `remove` or `clear` deleted it. Optional because iOS and web do not report it.                      | 1.0.0 |
| **`legacyEntriesKept`**     | <code>number</code>                                                                                        | Android only: keys whose `cap_sec` entry is still stored after its migration to `cap_sec_v2` in this process, because the deletion of the older storage is not switched on yet or the delete failed. A key leaves the count once `remove` or `clear` deletes the entry. Optional because iOS and web do not report it.                                                                    | 1.0.0 |
| **`keyBackend`**            | <code>'none' \| 'secureEnclave' \| 'software' \| 'unusable' \| 'keystoreAes' \| 'keystoreRsaLegacy'</code> | Key that encrypts values. On iOS `secureEnclave`, `software` (the simulator fallback), or `unusable` once the key kept refusing on an unlocked device and values fall back to plaintext for the rest of the process. On Android `keystoreAes`, or `keystoreRsaLegacy` while only the upstream RSA key exists. `none` means no key exists yet or it could not be looked up at this moment. |       |
| **`accessGroupMode`**       | <code>'default' \| 'explicit' \| 'n/a'</code>                                                              | `explicit` when new items go to the app-private `&lt;team id&gt;.&lt;bundle id&gt;` keychain access group, `default` when the plugin fell back to the app's default access group or could not determine it yet. `n/a` on Android.                                                                                                                                                         |       |


### Type Aliases


#### KeychainAccessibility

Keychain accessibility class of a stored item on iOS.

| Value                              | iOS constant                                        |
| ---------------------------------- | --------------------------------------------------- |
| `whenUnlocked`                     | `kSecAttrAccessibleWhenUnlocked`                    |
| `whenUnlockedThisDeviceOnly`       | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`      |
| `afterFirstUnlock`                 | `kSecAttrAccessibleAfterFirstUnlock`                |
| `afterFirstUnlockThisDeviceOnly`   | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`  |
| `whenPasscodeSetThisDeviceOnly`    | `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`   |

Android and web accept the value and ignore it.

<code>'whenUnlocked' | 'whenUnlockedThisDeviceOnly' | 'afterFirstUnlock' | 'afterFirstUnlockThisDeviceOnly' | 'whenPasscodeSetThisDeviceOnly'</code>

</docgen-api>

## Example

```ts
const key = 'username';
const value = 'hellokitty2';

SecureStoragePlugin.set({ key, value }).then((success) => console.log(success));
```

```ts
SecureStoragePlugin.set({
  key: 'token',
  value: 'abc',
  accessibility: 'whenUnlockedThisDeviceOnly',
});
```

```ts
const key = 'username';
SecureStoragePlugin.get({ key })
  .then((value) => {
    console.log(value);
  })
  .catch((error) => {
    console.log('Item with specified key does not exist.');
  });
```

```ts
async getUsername(key: string) {
  return await SecureStoragePlugin.get({ key });
}
```

## Platform specific information

### iOS

Items are generic passwords in the keychain. The key is stored in the account and generic attributes as UTF-8 data, items are not synchronizable, and items written by this fork carry the label `better-capacitor-secure-storage-plugin`. This is the shape SwiftKeychainWrapper used, so the query of upstream 0.13.0 finds every `cap_sec` item, whatever its access group.

#### Storage layout

| Service           | Holds                                                                                | Access group                 |
| ----------------- | ------------------------------------------------------------------------------------ | ---------------------------- |
| `cap_sec_v2`      | every value this release writes, by `set` or by the migration                        | the app-private group        |
| `cap_sec`         | legacy items: values of upstream 0.5.0 to 0.13.0 and of earlier builds of this fork | any group the app can access |
| the app bundle id | legacy items: values of upstream up to 0.4.0                                         | any group the app can access |

- `get` reads `cap_sec_v2`, the item in the app-private group first, then one in any other group. Only a key without a `cap_sec_v2` item falls back to its legacy items, see Migration below. A `cap_sec_v2` item that cannot be decrypted rejects as unreadable and never falls back, because a legacy item may hold an older value.
- `set` writes `cap_sec_v2` only.
- `keys` lists the keys of `cap_sec_v2` and `cap_sec`, each key once. Bundle id items are not listed until `get` copied them.
- `remove` deletes the `cap_sec_v2` item and every legacy item of the key, in `cap_sec` in any group and in the bundle id service, in both phases of the migration. It deletes the legacy items first and the `cap_sec_v2` item last. When a legacy item cannot be deleted, `remove` rejects with `Remove failed` and keeps the `cap_sec_v2` item, so a later `get` returns the newer value and never the older legacy one.
- `clear` deletes every item in `cap_sec_v2` and `cap_sec`, in any group, and the bundle id items of the keys it found there, in both phases. It also deletes `cap_sec_v2` last, and keeps it and rejects with `error` when a legacy deletion fails. A bundle id item whose key is in neither service survives `clear`, and `get` can still return it. An app that needs a hard wipe, for example on logout, also calls `remove({ key })` for every key it knows.

#### Access group

The plugin keeps its items in the app-private access group `<team id>.<bundle id>`. At the first call it adds a throwaway item without a group, reads back the group the keychain chose, takes the team prefix before the first `.` and appends `Bundle.main.bundleIdentifier`. A second throwaway write into that group confirms the app may use it. Both items are deleted right away and the result is cached for the process.

The group matters when the app's entitlements list `keychain-access-groups`. The first entry becomes the default group for every write without an explicit group, and that entry is usually shared with an extension. Upstream wrote items without an explicit group, so they may sit in that shared group, in the app-ID group, or in both.

New writes, the Secure Enclave key and the copies the migration makes all use the app-private group. Reads search every group the app can access. When the throwaway items fail, the app has no team prefix or bundle id, or a later write into the group returns `errSecMissingEntitlement` (-34018) or `errSecParam`, the plugin logs it once and falls back to the default group for the rest of the process. `getDiagnostics()` reports `accessGroupMode: 'default'` in that case. The plugin does not cache a probe that hits a locked keychain. The call waits for unlock instead.

After reinstalling an app, the data stored in the keychain are not deleted automatically. To clear the data the following code has to be added to AppDelegate.swift. This is just an example, there are multiple ways how it can be achieved.

```swift
import Security

if !UserDefaults.standard.bool(forKey: "firstTimeLaunchOccurred") {
    for service in ["cap_sec_v2", "cap_sec"] {
        SecItemDelete([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
        ] as CFDictionary)
    }

    UserDefaults.standard.set(true, forKey: "firstTimeLaunchOccurred")
}
```

#### Storage format

- `encryptValues: false` (opt-out) stores the value as plain UTF-8, the same as upstream.
- `encryptValues: true` (default) stores the magic prefix `0x00 0x53 0x4B 0x01` followed by an ECIES ciphertext, algorithm `eciesEncryptionCofactorVariableIVX963SHA256AESGCM`. The key is a P-256 key in the Secure Enclave with the tag `capacitor-secure-storage-plugin.v1`, created in the app-private group with `.privateKeyUsage` and no other flag.
- The key class follows the configured item class. It is `whenUnlockedThisDeviceOnly` by default and with `whenUnlocked` or `whenPasscodeSetThisDeviceOnly`, and `afterFirstUnlockThisDeviceOnly` when the configuration asks for `afterFirstUnlock` or `afterFirstUnlockThisDeviceOnly`. The class is fixed when the key is created on first use. Changing the configuration later does not change an existing key.
- The plugin looks the key up in the app-private group first and then in every group, so a key created by an earlier build is reused and never duplicated. Only encryption creates a key, decryption never does, because a new key cannot open old ciphertext. The plugin serialises lookup and creation across the process. It never deletes the key, `clear` included. On the simulator it uses a software key when the Secure Enclave is not available.
- Readers accept both formats at all times, whatever `encryptValues` says.
- With `encryptValues` on, a class without `ThisDeviceOnly` gains nothing. The Secure Enclave key never leaves the device, so items restored from a backup onto another device cannot be decrypted there. See Unreadable and lost items below. Use a `ThisDeviceOnly` class together with encryption.

#### What the encryption protects against

Encryption with a Secure Enclave key defeats attacks that copy keychain data off the device or out of it: a keychain dump tool that prints item data, a backup, a forensic image read offline, and a device migration. They all get ciphertext only, and the private key cannot leave the Secure Enclave. Together with `whenUnlockedThisDeviceOnly` the items are also not in backups at all and are unreadable while the device is locked.

It does not stop code that runs on a jailbroken, unlocked device with access to the app's keychain group. A hook inside the app process, or a tool signed with the app's group or a wildcard group, can ask the Secure Enclave to decrypt exactly the way the plugin does. Jailbreak detection, runtime integrity checks and server-side limits on PIN attempts are the controls for that case, and this plugin provides none of them.

#### Migration

The plugin copies legacy items into `cap_sec_v2` in two phases, so the legacy items stay on the device until most users run a version that has already made its copies.

- Phase 1, this release and the default: the plugin never modifies a legacy item. Nothing in `cap_sec` or in the bundle id service is deleted, re-encrypted, re-classed or relabelled. Only `remove` and `clear`, which the app asks for, delete legacy items.
- Phase 2, a later app version: after a verified write into `cap_sec_v2`, and in the sweep for keys that already have their `cap_sec_v2` item, the plugin deletes every `cap_sec` copy of the key, in any group, and its bundle id item. This code ships and is tested, but it stays off until the constant `deletesLegacyCopies` in `SecureStorageVault.swift` is set to `true` in the app version that follows the migration release, once most users have migrated. The TODO for it is SS-12183.

A key is copied only while it has no `cap_sec_v2` item. The plugin lists every copy of the key in `cap_sec` across every group the app can access, together with its copies in the bundle id service, and picks one. A `cap_sec` copy that carries this fork's label, written by an earlier build of this fork, wins over copies without it, and among labelled copies the newest modification date wins. When no copy carries the label, the winner is the copy upstream 0.13.0 returned: the plugin runs the 0.13.0 query (service, account and generic, not synchronizable, no access group, limit one) and takes the copy it finds. That is the value the app has been using, and the newest modification date can belong to a different copy. A bundle id copy only counts when `cap_sec` has none, whatever its date, and the same 0.13.0 query picks among bundle id copies.

The plugin adds the winning value to `cap_sec_v2` in the app-private group, with the configured class but never looser than the class of the winning copy (see below), and encrypted when `encryptValues` is on. It reads the new item back and decodes it. Only when that value matches does the key count in `migrated`, do the other legacy copies whose value differs from the winner count in `conflictingDuplicates`, and, in phase 2, are the legacy copies deleted. An item that does not verify is deleted again, and the next `get` or sweep tries again. A failed write changes nothing.

The copy is made in two places.

- `get` copies its key inside the call, so the first read after an upgrade already returns the value 0.13.0 returned and never another copy left in a second group. A migration problem never fails the `get`, the value read is returned anyway. While protected data is known to be unavailable `get` only reads.
- A sweep runs once per process, whatever `encryptValues` says. It waits until an app call has completed and about 1.5 seconds have passed without another app call, so on a cold start it never delays the app's first call and never runs between two calls the app makes in a row. When the app makes no call it waits about five seconds after load instead, longer while an app call came within the last 1.5 seconds. Then it runs once the queue of app calls has drained, in the foreground, and only once protected data is known to be available. It lists the keys of `cap_sec_v2`, `cap_sec` and the bundle id service and copies every `cap_sec` key that has no `cap_sec_v2` item. A key that already has one costs nothing beyond the listings: no read, no decryption and no write, so the legacy items phase 1 keeps cause no work on later launches. In phase 2 the sweep deletes the legacy copies of those keys. The sweep skips locked keys and runs again on a later drain while the app makes no call, at most three times per launch.

When the winning legacy copy cannot be decoded, the key reads as `UNREADABLE` and nothing is copied. No other copy is promoted, because that would bring back a stale value, and no copy is rewritten. A `set` of the key writes its `cap_sec_v2` item.

Upstream versions up to 0.4.0 wrote the bundle id service items. The sweep only copies `cap_sec` keys, so a bundle id item of a key that has no `cap_sec` copy is copied only by the first `get` of that key. Bundle id items of keys that have no `cap_sec_v2` item stay untouched in both phases, because other code in the app may own them.

A migration never gives an item a looser class. The plugin combines the class of the winning copy with the configured default and takes the stricter value on each of two axes. The unlock requirement goes from after first unlock to when unlocked to when a passcode is set. The device binding goes from migratable to `ThisDeviceOnly`. A current class the plugin does not know is replaced by the configured default. For example an upstream item with `afterFirstUnlock` is copied as `whenUnlockedThisDeviceOnly` when that is the configured default, and a `whenUnlocked` item combined with a configured `afterFirstUnlockThisDeviceOnly` becomes `whenUnlockedThisDeviceOnly`. The same applies to a copy that carries this fork's label, so a per-call `afterFirstUnlock` that an earlier build of this fork wrote into `cap_sec` is tightened as well. A plain `set` always writes exactly the requested or the configured class, and the copy never changes a `cap_sec_v2` item.

With `encryptValues` off the migration still copies values into the app-private group with the tightened class. It keeps plaintext as plaintext and copies encrypted items as they are. A `cap_sec_v2` item that holds plaintext while `encryptValues` is on, a plaintext fallback or a value written with `encryptValues` off, is encrypted in place with its class by its next `get` once encryption works. The sweep leaves it alone.

#### Locked device

While the device is locked, keychain items with an unlock-bound class fail with `errSecInteractionNotAllowed` (-25308). A silent push, a background fetch or an over-the-air bundle that restarts the JavaScript can run the app in that state. The plugin does not report such calls as missing keys. It queues them strictly in order and they wait for unlock. There is no absolute timeout. A call that is still locked stays at the head of the queue and everything behind it waits.

The plugin tracks protected data from `protectedDataWillBecomeUnavailable` and `protectedDataDidBecomeAvailable`. It also reads `UIApplication.isProtectedDataAvailable` on the main thread at load, on `willEnterForeground`, `didBecomeActive` and `didEnterBackground`, and on the retry timer below. The plugin queue never waits for the main thread, it reads a locked flag. Until the first read arrives the state counts as available and the keychain's own -25308 decides. When the configured default class is `whenUnlocked`, `whenUnlockedThisDeviceOnly` (the default) or `whenPasscodeSetThisDeviceOnly`, the plugin holds calls back while protected data is known to be unavailable, without touching the keychain. With `afterFirstUnlock` or `afterFirstUnlockThisDeviceOnly` calls run right away, and the plugin queues only a call that still gets -25308. An app that must read values while the device is locked has to opt out with `"accessibility": "afterFirstUnlock"`.

While any call waits, a one-second timer on the plugin's queue retries the queue and re-reads the protected-data state, so a missed notification cannot leave calls waiting after unlock. The timer stops when the queue is empty.

#### Unreadable and lost items

An item that decrypts to garbage, belongs to a Secure Enclave key that no longer exists, or holds bytes that are not UTF-8 rejects with `Item with given key does not exist` and the code `UNREADABLE`. The plugin deletes nothing in that case and a `set` overwrites the item.

A failed decryption is not final on the first try. The plugin drops its cached key reference, looks the key up again and retries twice, after about 50 ms and 200 ms, and counts each retry in `decryptRetries`. A call that waits after such a failure makes a single attempt without the delays each time the timer runs it again. Only these results are final: `errSecParam` (-50) or `errSecDecode` (-26275) after the retries, which mean a wrong key or corrupt ciphertext, a key that does not exist (-25300), the magic prefix without ciphertext, and plaintext that is not UTF-8. The plugin handles every other failure, a failed key lookup included, like a locked device. The call waits. If it never recovers, the key counts as unusable (see below), or, when the key still opens fresh ciphertext, the lost-item escape below ends the call. Before calling a failure final the plugin checks that protected data is known to be available and that a throwaway write with the `whenUnlockedThisDeviceOnly` class is not refused with `errSecInteractionNotAllowed`. Otherwise it treats the failure as a locked device and the call waits.

A device migration such as Quick Start can carry `ThisDeviceOnly` items that stay visible but fail with -25308 forever, also on an unlocked device. A call stuck on such an item would wait forever. When a call returns -25308 while protected data is known to be available and the throwaway write is not refused with `errSecInteractionNotAllowed`, the plugin retries it on the next three timer ticks. If it is still refused, the plugin classifies the item as lost. `get` rejects with `Item with given key does not exist` and the code `UNREADABLE`, `remove` and `clear` delete what they can, the legacy items first and `cap_sec_v2` last, keep `cap_sec_v2` when a legacy deletion fails with an error other than -25308, and resolve, `set` deletes the `cap_sec_v2` item of the key and writes a fresh one while the legacy items stay as after any `set`, and `keys` resolves with an empty list. Retries only count once per tick and only while the throwaway write agrees, so a stale protected-data signal on a locked device never turns into a lost item.

The Secure Enclave key can be in the same state: after a Quick Start the key item is visible, but its lookup, or every decryption with it, returns -25308 on an unlocked device. The plugin counts those results the same way, once per tick and only while the throwaway write agrees. A key lookup that fails during a decryption, and a decryption failure that is not final (see above), count the same way, so a broken key ends one call after the tick retries and the calls behind it do not each wait through their own. For such a decryption failure the key first has to fail to open ciphertext made for it on the spot, so a failure that only one item shows ends that call through the lost-item escape and leaves the key in use. After the first counted result and three more it treats the key as unusable for the rest of the process: `set` stores plaintext with at least `whenUnlockedThisDeviceOnly` and counts it in `plaintextFallbacks`, ciphertext reads as `UNREADABLE` right away, a fault is logged once and `getDiagnostics()` reports `keyBackend: 'unusable'`. A key that decrypts again resets the count, and so does a key lookup that finds the key, except the fresh lookups of the decryption retries. The plugin never deletes the key, because a misjudged transient would make every ciphertext unreadable, and the next launch tries the key again.

#### Fallbacks

- When key generation or encryption fails for a reason other than a locked device, `set` stores the value as plaintext with at least the `whenUnlockedThisDeviceOnly` class instead of rejecting. The plugin logs a fault and counts it in `plaintextFallbacks`. The next `get` of the item encrypts it in place once encryption works again. A migration follows the same rule.
- Every new ciphertext is decrypted once in memory before it is written. When that check fails on an unlocked device, the write takes the plaintext fallback above, so ciphertext the key cannot open never replaces a readable value. When the check fails because the device is locked, the call waits.
- A key that is unusable for the process, see Unreadable and lost items, takes the same plaintext fallback.
- When the app-private access group is not available, the plugin uses the default group, see Access group above.

#### Rejection codes

The messages are the same as in upstream. iOS adds a `code` to the error:

| Code                        | When                                                                                       |
| --------------------------- | ------------------------------------------------------------------------------------------ |
| `NOT_FOUND`                 | `get` or `remove` of a key that has no item.                                              |
| `UNREADABLE`                | `get` of an item that cannot be decrypted or is lost. The message says the key does not exist. |
| `UNSUPPORTED_ACCESSIBILITY` | Unknown `accessibility` in the call or in the plugin configuration.                       |
| `STORAGE_ERROR`             | Any other keychain failure, message `error` or `Remove failed`.                           |
| `LOCKED`                    | Reserved for a future fail-fast option. The plugin waits for unlock instead and never emits it today. |

#### Diagnostics

`getDiagnostics()` resolves right away, also while other calls wait for unlock. The counters start at zero with each app process.

| Field                | Meaning                                                                                               |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| `parked`             | Calls that had to wait for unlock.                                                                    |
| `migrated`           | Keys copied into `cap_sec_v2` from `cap_sec` or the bundle id service and verified.                   |
| `duplicatesResolved` | Legacy copies deleted once their key had a verified `cap_sec_v2` item. Stays `0` in phase 1.          |
| `lostItems`          | Calls completed as lost after the retries.                                                            |
| `decryptFailures`    | Reads of an item that could not be decrypted or decoded.                                              |
| `plaintextFallbacks` | Values written as plaintext because encryption failed.                                                |
| `decryptRetries`     | Decryptions repeated with a fresh key lookup after a failure on an unlocked device.                   |
| `conflictingDuplicates` | Legacy copies whose value differed from the winning copy when their key was copied.                |
| `legacyCopiesKept`   | Keys that have their `cap_sec_v2` item while legacy copies are still stored, each key once. In phase 1 every such key, in phase 2 only keys whose delete failed. |
| `keyBackend`         | `secureEnclave`, `software` on the simulator, `unusable` once the key kept refusing or failing on an unlocked device, or `none` when no key exists or the lookup was refused. |
| `accessGroupMode`    | `explicit` for the app-private group, `default` after a fallback or before the group is known.        |

Web resolves zeros with `keyBackend: 'none'` and `accessGroupMode: 'default'`. Android reports `keyBackend` as `keystoreAes`, `keystoreRsaLegacy` or `none`, `accessGroupMode` as `n/a`, and `parked`, `duplicatesResolved` and `plaintextFallbacks` as zero. `decryptRetries`, `conflictingDuplicates` and `legacyCopiesKept` are optional in the TypeScript type, because Android does not report them.

#### Downgrades

Upstream 0.13.0 and earlier builds of this fork read `cap_sec`, not `cap_sec_v2`. During phase 1 the legacy items stay exactly as they were before the upgrade, so going back to such a build finds the values as they were then. Values written by `set` after the upgrade are not there. If the older build then changes values and the app is upgraded again, the `cap_sec_v2` item still wins for every key that has one, so those changes are not seen, and a key the older build removed comes back. Keys the older build added are copied as usual. After phase 2 deleted the legacy items, going back finds no values.

The values this release encrypts live in `cap_sec_v2` only, so an older build never sees their ciphertext. To stop encrypting, set `encryptValues` to `false`. New writes are plaintext again and the fork still reads the encrypted items that remain.

#### Tests

The iOS tests come in two parts.

The unit tests in `ios/Tests/SecureStoragePluginTests` cover configuration parsing, the accessibility mapping, the class combination rule for all 25 pairs, the locked-device queue, the retry timer, the lost-item escape, the sweep scheduling and its wait for a quiet period after the app's calls, the decryption retries and which failures are final, the unusable key, the ciphertext check before a write, the app-private group name, the rejection codes, `getDiagnostics`, the keychain service names and that older copies are kept by default. They inject the protected-data signal, the unlock probe, the timer, the key lookup and the decryption, use in-memory keys, and need no keychain. Set `SIMULATOR_ID` to the UDID of an available simulator (`xcrun simctl list devices available`) and run them from the repository root:

```bash
xcodebuild test -scheme BetterCapacitorSecureStoragePlugin -destination "id=$SIMULATOR_ID"
```

The keychain tests cannot run in the Swift package test bundle, because it has no keychain entitlement and every keychain call fails with -34018. They live in `ios/Tests/harness` as a small binary that is linked with embedded entitlements and spawned on a booted simulator:

```bash
ios/Tests/harness/build.sh
SIMULATOR_ID=<simulator udid> ios/Tests/harness/build.sh
```

Without `SIMULATOR_ID` the script uses the booted simulator. The first run clones SwiftKeychainWrapper 4.0.1 into `ios/Tests/harness/.build`, so it needs network access once. The folder is git ignored. The clone lets the harness write legacy items with the same library upstream used. The script prints every failed check and the pass count, and exits non-zero when a check fails.

`ios/Tests/harness/entitlements.plist` mirrors a typical app with an extension: a fake team prefix, the application identifier that the plugin turns into its app-private group, a first `keychain-access-groups` entry that acts as the shared default group, and a second entry for older copies in one more group. Most sections run the default configuration, phase 1. The upgrade has its own sections, A to I. `pin` and `token`, each with different values and dates in the app-ID group and the shared group, stay byte-identical (data, class, group, label and date) after `get` and after the sweep, while `cap_sec_v2` gets one encrypted item per key in the app-private group that holds the value the 0.13.0 query returns. The sweep of the next launch writes and decrypts nothing. `set` changes only `cap_sec_v2`, and the 0.13.0 query still returns the pre-upgrade value, as after a downgrade. `remove` and `clear` delete in both services and `keys` lists their union before and after the copies. A key only in the bundle id service is copied and its item stays. A phase 2 vault, switched on through the vault configuration so the deletion code keeps its coverage, deletes every legacy copy after the write and in the sweep, counts them in `duplicatesResolved` and leaves the `cap_sec_v2` item as it was. A lost `cap_sec_v2` item is replaced by `set` and the legacy items stay, and with the fallback to the default group `cap_sec_v2` lives there. With an injected failure of a legacy deletion, `remove` and `clear` reject and keep the `cap_sec_v2` item, and `get` still returns the newer value. The other sections cover the ranking of legacy copies, mixed plaintext and encrypted items, undecryptable ciphertext in either service, other services and an item without a service surviving `clear`, the never-loosens matrix, the key class, the plaintext fallback and its encryption by a later `get`, the ciphertext check and the deletion of a copy that does not verify, decryption retries, lost items, and a key that keeps failing versus a failure of one item. It cannot simulate a locked device. The harness simulates a Quick Start key with a stubbed key lookup, and the unit tests cover the rest of that logic with injected signals.

> **Warning**
> Up to upstream version v0.4.0 there was standard keychain used. Since v0.5.0 there is separate keychain wrapper, so keys() method returns only keys set in v0.5.0 or higher version.

### Android

Values live in the SharedPreferences file `cap_sec_v2` (`MODE_PRIVATE`). Each value is encrypted with an AES-256-GCM key in AndroidKeyStore. Entries written by upstream versions stay in the older file `cap_sec` until the plugin deletes them, see Two-phase migration below. `keys()` lists the entries of both files, each key once, and `contains` checks both.

#### Storage format

A value is stored as the string `v2:` followed by base64 of the 12 byte IV, the ciphertext and the 16 byte GCM tag. The key alias is `<packageName>_cap_sec_aes_v2`, with purposes encrypt and decrypt, GCM, no padding and randomized encryption, so AndroidKeyStore picks a fresh IV for every write. The additional authenticated data is `v2:` plus the storage key, so an encrypted value copied to another key does not decrypt. The key is created on the first write and the plugin never deletes it, `clear()` empties the preferences files only.

`get` reads `cap_sec_v2` first. Only when the key is not there does it read `cap_sec`. An entry in `cap_sec_v2` that cannot be decrypted rejects as unreadable and never falls back to `cap_sec`, because the older entry may hold an older value.

Readers detect the format of a `cap_sec` entry, in this order:

1. starts with `v2:` → AES-GCM, as written into `cap_sec` by earlier builds of this fork. The `:` is not in the base64 alphabet, so no older entry starts with it.
2. contains a character other than `A-Z`, `a-z`, `0-9`, `+`, `/`, `=` and whitespace, or is not empty but decodes to zero bytes → unreadable. `android.util.Base64` skips such characters instead of failing, so without this check a corrupt entry would read as a shorter value or as `""`.
3. the RSA key pair of upstream versions (`<packageName>_cap_sec`) exists and the base64 decodes to a non-zero multiple of 256 bytes → RSA/ECB/PKCS1Padding in 256 byte blocks, as upstream wrote it.
4. the base64 decodes to valid UTF-8 → plaintext entry. Upstream fell back to plaintext base64 silently when AndroidKeyStore failed to initialise, so some installs have such entries.
5. anything else → unreadable.

When the RSA decrypt fails on a 256 byte multiple, step 4 still runs, because a plaintext value of exactly that length is possible. Undecryptable RSA output is random and practically never valid UTF-8.

#### Migration

The plugin encrypts an entry read from `cap_sec` with the AES key, decrypts it again and writes it to `cap_sec_v2` with `commit()` before `get` resolves. It writes only when the decrypted bytes equal the value that was read. Otherwise nothing is written, `get` returns the value of the legacy entry and the plugin counts the key in `migrationSkipped` until the entry is migrated, overwritten or removed.

Before the first migration write of the process the plugin encrypts and decrypts a constant with a fixed AAD. Until that self-test passes the plugin migrates no entry, reads older entries as they are and stops the background walk. The test runs again on the next migration, so a keystore that recovers is used again. `set` does not run the self-test, but it decrypts its own ciphertext once in memory before writing and rejects when the result differs.

On the first storage call of the process the plugin also walks `cap_sec` on a background thread and migrates every entry that has no `cap_sec_v2` entry yet. The walk takes the storage lock per entry, so calls from JavaScript are not held up behind it, and a key written by `set` in the meantime is left alone. When the AES key cannot be created, the check fails or the write fails, `get` still returns the old value until a later read or walk migrates it. The RSA key is kept for that reason, and the plugin never generates a new RSA key.

The upgrade needs nothing from the app. Users stay logged in and see no prompt.

#### Two-phase migration

The constant `SecureStore.DELETE_LEGACY_STORAGE` decides whether the plugin deletes the older storage. It is `false` in this release.

Phase 1, this release (`false`):

- A migration writes the `cap_sec_v2` entry and leaves the `cap_sec` entry exactly as it was. It is not deleted, rewritten or re-encrypted, and neither is the RSA key.
- `set` writes to `cap_sec_v2` only. The `cap_sec` entry of that key keeps its older value.
- `remove` deletes the key from both files. `clear` empties both files. Both are wipes the app asked for, so the older copies go too.
- Entries the plugin cannot read, or whose migration was skipped, stay in `cap_sec`.
- An app version that still reads `cap_sec` finds the values as they were before the upgrade, without later changes.

Phase 2, a later app version (`true`, tracked in SS-12183, planned once most users have migrated):

- After a verified write to `cap_sec_v2`, by a migration or by `set`, the plugin deletes the `cap_sec` entry of that key. A `cap_sec` entry whose key already has a readable `cap_sec_v2` entry, as phase 1 left them, is deleted by `get` and by the background walk.
- Entries the plugin cannot read, or whose migration was skipped, still stay.
- Once `cap_sec` has no entry left, the plugin deletes the RSA key `<packageName>_cap_sec` and the `cap_sec` file. A failure is logged and tried again on the next occasion.

The phase 2 code ships in this release, switched off, and the unit tests run it with the switch on.

#### Failure behaviour

- Reads fail open for older formats as described above.
- Writes fail closed. If the AES key cannot be created or used, or the fresh ciphertext does not decrypt back to the same bytes, `set` rejects with `error` and code `STORAGE_ERROR` and the previous entry stays untouched. The plugin never writes plaintext and never falls back to RSA. This is the one user-visible change versus upstream on Android, and it is intentional. It only happens on devices whose AndroidKeyStore cannot create or use the AES key, where upstream stored the value as plaintext base64.
- The plugin tries keystore calls that fail with a transient error up to three times (again after 50 ms and 200 ms). Nothing is latched. The next call tries the keystore again, so a keystore that fails at startup does not degrade the whole process.
- Which errors count as permanent depends on the path. AES-GCM: only a wrong tag (`AEADBadTagException`) and a missing AES key. AndroidKeyStore reports most other `doFinal` failures as `IllegalBlockSizeException`, so that and a plain `BadPaddingException` are retried, and if they persist the read ends as `UNREADABLE` counted in `decryptFailures`, not in `lostItems`. Legacy RSA: `BadPaddingException` and a missing RSA key are permanent. `IllegalBlockSizeException` is permanent only when the stored bytes are valid UTF-8, so a plaintext entry of 256 × n bytes still reaches the UTF-8 reader. For any other entry it is retried and, if it persists, counted in `decryptFailures`, not in `lostItems`. On Android 13 and later an error caused by an `android.security.KeyStoreException` that reports `isTransientFailure()` is always retried.
- After an AES encrypt, the self-test or the check of a migrated entry failed on every attempt, migrations and the background walk make a single attempt without delays until an AES operation succeeds again, so a broken keystore does not add about 250 ms to every read of an older entry. An older entry the background walk cannot read in that single attempt, for a reason that is not permanent, is not counted in `decryptFailures`, the next `get` reads it with all three attempts. `get` of the value itself and `set` keep all three attempts.
- An entry that exists but cannot be decrypted (a wrong GCM tag, a missing AES key, a failing RSA decrypt) rejects `get` with `Item with given key does not exist` and code `UNREADABLE`. The plugin deletes neither the entry nor the keys. `set` overwrites the entry and `remove` deletes it. A missing key rejects with the same message and code `NOT_FOUND`. The messages are the same as upstream, only the codes are new.
- Undecryptable entries are expected after a device-to-device transfer that copied `cap_sec.xml` or `cap_sec_v2.xml` without the keystore key. Upstream read them as missing too.
- `load()` does no keystore work. The plugin creates the store on the first call. All storage calls run in order on one plugin thread per process, shared by every plugin instance.

#### No lock-bound key flags

The AES key does not use `setUnlockedDeviceRequired`, `setUserAuthenticationRequired` or StrongBox:

- JavaScript can keep running in the background on Android, so apps may read values while the screen is locked. A key bound to the unlocked state would fail those reads, and the app would treat the value as missing.
- On Android 12 to 14 keys with these flags have been reported to become permanently unusable on some devices, for example after lock screen changes. That would lose every stored value.

The key stays non-exportable inside AndroidKeyStore (hardware-backed where the device supports it), so a copy of `cap_sec_v2.xml` alone does not reveal values. `cap_sec.xml` keeps the upstream protection of its entries during phase 1.

#### Keep `cap_sec.xml` and `cap_sec_v2.xml` out of backups and transfers

`android:allowBackup="false"` does not stop device-to-device transfer on Android 12 and later. The copied files cannot be decrypted on the new device, because the keys stay behind. Exclude both files in the app, not in the plugin.

`android/app/src/main/res/xml/data_extraction_rules.xml` (Android 12 and later):

```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="cap_sec.xml" />
        <exclude domain="sharedpref" path="cap_sec_v2.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="cap_sec.xml" />
        <exclude domain="sharedpref" path="cap_sec_v2.xml" />
    </device-transfer>
</data-extraction-rules>
```

`android/app/src/main/res/xml/backup_rules.xml` (Android 11 and earlier):

```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <exclude domain="sharedpref" path="cap_sec.xml" />
    <exclude domain="sharedpref" path="cap_sec_v2.xml" />
</full-backup-content>
```

`AndroidManifest.xml`:

```xml
<application
    android:allowBackup="false"
    android:dataExtractionRules="@xml/data_extraction_rules"
    android:fullBackupContent="@xml/backup_rules"
    ...>
```

#### Diagnostics

`getDiagnostics()` resolves with counters of the current process: `migrated` (verified writes of a `cap_sec` entry into `cap_sec_v2`), `lostItems` (distinct keys whose entry is intact but does not decrypt), `decryptFailures` (distinct keys in an unknown format or failing after all retries), `migrationSkipped` (Android only, legacy entries still stored whose migration was skipped because the self-test, the encryption, the decrypt check or the write failed. A key leaves the count once a later migration or `set` writes its `cap_sec_v2` entry, or `remove` or `clear` deletes it), `legacyEntriesKept` (Android only, distinct keys whose `cap_sec` entry is still stored after its migration. In phase 1 every migrated key stays in the count until `remove` or `clear` deletes it. In phase 2 only keys whose `cap_sec` entry could not be deleted) and `keyBackend` (`keystoreAes`, `keystoreRsaLegacy` or `none`). `parked`, `duplicatesResolved` and `plaintextFallbacks` are always `0` and `accessGroupMode` is `n/a` on Android.

#### Downgrades

Upstream versions and earlier builds of this fork do not read `cap_sec_v2`. During phase 1 the `cap_sec` entries stay, so going back to such a version finds the values as they were before the upgrade. Values written by `set` after the upgrade are not there. After phase 2 deleted `cap_sec`, going back finds no values.

#### Tests

```bash
cd android
./gradlew test                  # JVM tests of the format, reader order and migration
./gradlew connectedAndroidTest  # real AndroidKeyStore, needs a device or emulator
```

### Web

There is no secure storage in browser (not because it is not implemented by this plugin, but it does not exist at all). Values are stored in LocalStorage, but they are at least base64 encoded. Plugin adds 'cap_sec' prefix to keys to avoid conflicts with other data stored in LocalStorage.

## Releasing

Publishing is manual. Run the tests, bump the version, publish.

```bash
npm run build
cd android && ./gradlew test && cd ..
xcodebuild test -scheme BetterCapacitorSecureStoragePlugin -destination "id=$SIMULATOR_ID"
npm version X.Y.Z
npm publish --access public
git push origin master --tags
```

`npm version` updates `package.json` and `package-lock.json`, commits and tags. `prepublishOnly` rebuilds `dist` before the publish. Rename the `## X.Y.Z (unreleased)` heading in `CHANGELOG.md` to `## X.Y.Z` before you run it.
