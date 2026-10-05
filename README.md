[![npm version](https://badge.fury.io/js/better-capacitor-secure-storage-plugin.svg)](https://badge.fury.io/js/better-capacitor-secure-storage-plugin)

# better-capacitor-secure-storage-plugin

Capacitor plugin for storing string values securely on iOS and Android.

## Fork notice

This is a Skip Pay fork of [martinkasa/capacitor-secure-storage-plugin](https://github.com/martinkasa/capacitor-secure-storage-plugin), created to harden the Keychain/Keystore configuration after a penetration test. It keeps the same JavaScript API and the plugin name `SecureStoragePlugin`, so switching from upstream is an import change.

What differs from upstream:

- iOS values can be encrypted at rest with a Secure Enclave key (`encryptValues`, on by default).
- The iOS keychain accessibility class is configurable, globally in the plugin configuration and per `set` call (upstream issue [#151](https://github.com/martinkasa/capacitor-secure-storage-plugin/issues/151)). The default is the hardened `whenUnlockedThisDeviceOnly`, `afterFirstUnlock` stays available as an explicit opt-out.
- iOS no longer fails a read as "missing" while the device is locked. Calls that hit a locked keychain are queued and run in order after unlock.
- The SwiftKeychainWrapper dependency is gone. iOS talks to the keychain directly through Security.framework.
- With `encryptValues` on, plaintext items in the `cap_sec` service are encrypted when the plugin loads.
- Android encrypts with AES-256-GCM in AndroidKeyStore instead of chunked RSA, migrates RSA and plaintext entries, and rejects a write it cannot encrypt instead of storing it in plaintext.

The defaults on iOS are hardened: values are encrypted with a Secure Enclave key and stored with the `whenUnlockedThisDeviceOnly` class, so they are not available while the device is locked and do not leave the device in backups. To get the upstream behaviour, set `encryptValues` to `false` and `accessibility` to `afterFirstUnlock` in the plugin configuration. On Android values are encrypted with an AES-256-GCM AndroidKeyStore key and older entries are migrated on read, see Android below. Web behaves as in upstream 0.13.0.

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

| Prop                | Type                                                                    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Default                                   | Since |
| ------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ----- |
| **`accessibility`** | <code><a href="#keychainaccessibility">KeychainAccessibility</a></code> | Default keychain accessibility class for items written by the plugin (iOS only). `afterFirstUnlock` is available as an explicit opt-out, for example when the app must read values while the device is locked. An unknown value makes every storage call reject with `Unsupported accessibility value in plugin configuration`, only `getPlatform` still resolves.                                                                                                                     | <code>'whenUnlockedThisDeviceOnly'</code> | 1.0.0 |
| **`encryptValues`** | <code>boolean</code>                                                    | Encrypt stored values with a Secure Enclave key (iOS only). Enabled by default, set `false` to opt out. Plaintext items in the plugin's `cap_sec` keychain service are encrypted when the plugin loads. Items in the app bundle id service move into `cap_sec` and are encrypted lazily when `get` reads them. A migrated item keeps its keychain class when that class is stricter than the configured default. Android always encrypts with AndroidKeyStore, web ignores the option. | <code>true</code>                         | 1.0.0 |

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

The class is applied on every write. A per-call `accessibility` on `set` wins over the configured default. Existing items keep their class until they are written again, so changing the configured class affects new writes only. The exceptions are the migrations described under Migration below, and they never loosen a class. Android and web accept `accessibility` and ignore it, because Android already encrypts values with AndroidKeyStore and the browser has no keychain. `encryptValues` is iOS only.

## API

<docgen-index>

* [`get(...)`](#get)
* [`set(...)`](#set)
* [`remove(...)`](#remove)
* [`clear()`](#clear)
* [`keys()`](#keys)
* [`getPlatform()`](#getplatform)
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

| Param         | Type                          | Description        |
| ------------- | ----------------------------- | ------------------ |
| **`options`** | <code>{ key: string; }</code> | The key to remove. |

**Returns:** <code>Promise&lt;{ value: boolean; }&gt;</code>

--------------------


### clear()

```typescript
clear() => Promise<{ value: boolean; }>
```

Remove all values in the plugin's keychain service plus the legacy bundle id copies of those keys.
On iOS legacy items left only in the bundle id service are kept and `get` can still return them.

**Returns:** <code>Promise&lt;{ value: boolean; }&gt;</code>

--------------------


### keys()

```typescript
keys() => Promise<{ value: string[]; }>
```

List the keys of all values in the plugin's keychain service.
On iOS legacy items in the bundle id service are not listed.

**Returns:** <code>Promise&lt;{ value: string[]; }&gt;</code>

--------------------


### getPlatform()

```typescript
getPlatform() => Promise<{ value: string; }>
```

Get the implementation in use.

**Returns:** <code>Promise&lt;{ value: string; }&gt;</code>

--------------------


### Interfaces


#### SecureStorageSetOptions

| Prop                | Type                                                                    | Description                                                                                                                                                                                                           | Since |
| ------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| **`key`**           | <code>string</code>                                                     | Key under which the value is stored.                                                                                                                                                                                  |       |
| **`value`**         | <code>string</code>                                                     | Value to store.                                                                                                                                                                                                       |       |
| **`accessibility`** | <code><a href="#keychainaccessibility">KeychainAccessibility</a></code> | Keychain accessibility class for this item (iOS only). Overrides the `accessibility` plugin configuration for this call. An unknown value rejects with `Unsupported accessibility value`. Ignored on Android and web. | 1.0.0 |


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

Items are generic passwords in the keychain with service `cap_sec`. The key is stored in the account and generic attributes, items are not synchronizable and no access group is set.

After reinstalling an app, the data stored in the keychain are not deleted automatically. To clear the data the following code has to be added to AppDelegate.swift. This is just an example, there are multiple ways how it can be achieved.

```swift
import Security

if !UserDefaults.standard.bool(forKey: "firstTimeLaunchOccurred") {
    SecItemDelete([
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "cap_sec",
    ] as CFDictionary)

    UserDefaults.standard.set(true, forKey: "firstTimeLaunchOccurred")
}
```

#### Storage format

- `encryptValues: false` (opt-out) stores the value as plain UTF-8, the same as upstream.
- `encryptValues: true` (default) stores the magic prefix `0x00 0x53 0x4B 0x01` followed by an ECIES ciphertext (`eciesEncryptionCofactorVariableIVX963SHA256AESGCM`). The key is a P-256 key in the Secure Enclave with the tag `capacitor-secure-storage-plugin.v1`. Its access class is `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, so it is available whenever an item of any class is, and the item class carries the restriction. It is created on first use, looked up by tag afterwards and never deleted by the plugin. Lookup and creation are serialised across the whole process, so concurrent plugin instances share one key. On the simulator a software key is used instead.
- Readers accept both formats at all times, whatever `encryptValues` says.
- With `encryptValues` on, a class without `ThisDeviceOnly` gains nothing. The Secure Enclave key never leaves the device, so items restored from a backup onto another device cannot be decrypted there and reject with `Item with given key could not be decrypted`. A `set` overwrites them. Use a `ThisDeviceOnly` class together with encryption.
- An item that cannot be decrypted rejects with `Item with given key could not be decrypted`. A missing key rejects with `Item with given key does not exist` on every platform.

#### Migration

With `encryptValues` on, the plugin walks the `cap_sec` service when it loads and encrypts every plaintext item. Items already in the encrypted format are left alone, so the walk is safe to repeat. A key the keychain refuses while the device is locked is skipped and does not hold back other calls. It is encrypted on its next successful `get`. A plaintext item read by `get` is encrypted the same way right after the read.

With `encryptValues` off, the plugin never rewrites existing `cap_sec` items. The load walk does nothing and `get` does not rewrite a `cap_sec` item, as in upstream. The lazy bundle id move below still writes.

Items in the app bundle id service were written by upstream versions up to 0.4.0. They are moved lazily, as in upstream. When `get` asks for a key that is missing in `cap_sec` but exists in the bundle id service, the value is written into `cap_sec` with the configured settings. The old item is deleted only after that write succeeded. `remove` deletes the key in both services. `clear` deletes the bundle id copies of the keys it clears and leaves other bundle id items alone, so `get` can still return those.

A migration never gives an item a looser class. The plugin combines the item's current class with the configured default and takes the stricter value on each of two axes. The unlock requirement goes from after first unlock to when unlocked to when a passcode is set. The device binding goes from migratable to `ThisDeviceOnly`. A current class the plugin does not know is replaced by the configured default. For example an upstream item with `afterFirstUnlock` becomes `whenUnlockedThisDeviceOnly` when that is the configured default, and a `whenUnlocked` item combined with a configured `afterFirstUnlockThisDeviceOnly` becomes `whenUnlockedThisDeviceOnly`. A plain `set` always writes exactly the requested or the configured class.

#### Locked device

While the device is locked, keychain items with an unlock-bound class fail with `errSecInteractionNotAllowed` (-25308). A silent push can launch the app in that state. Such calls are not reported as missing keys. They are queued strictly in order and run after `protectedDataDidBecomeAvailable`, `willEnterForeground` or `didBecomeActive`. There is no timeout. A call that is still locked stays at the head of the queue and everything behind it waits.

When the configured default class is `whenUnlocked`, `whenUnlockedThisDeviceOnly` (the default) or `whenPasscodeSetThisDeviceOnly`, calls are held back while protected data is unavailable, without touching the keychain. With `afterFirstUnlock` or `afterFirstUnlockThisDeviceOnly` calls run right away, and only a call that still gets -25308 is queued. An app that must read values while the device is locked, for example when a silent push wakes it, has to opt out with `"accessibility": "afterFirstUnlock"`.

#### Never downgrade after encryption was used

A build without this fork cannot read encrypted items and cannot overwrite them either. Encryption is on by default, so do not switch back to upstream once this fork has written values with the defaults. To stop encrypting, set `encryptValues` to `false`. New writes are plaintext again and the fork still reads the encrypted items that remain.

#### Tests

The iOS tests come in two parts.

The unit tests in `ios/Tests/SecureStoragePluginTests` cover configuration parsing, the accessibility mapping, the class combination rule for all 25 pairs, the locked-device queue, the load walk and the plugin rejects. They need no keychain. CI runs them. Set `SIMULATOR_ID` to the UDID of an available simulator (`xcrun simctl list devices available`) and run them from the repository root:

```bash
xcodebuild test -scheme BetterCapacitorSecureStoragePlugin -destination "id=$SIMULATOR_ID"
```

The keychain tests cannot run in the Swift package test bundle, because it has no keychain entitlement and every keychain call fails with -34018. They live in `ios/Tests/harness` as a small binary that is linked with embedded entitlements and spawned on a booted simulator:

```bash
ios/Tests/harness/build.sh
SIMULATOR_ID=<simulator udid> ios/Tests/harness/build.sh
```

Without `SIMULATOR_ID` the script uses the booted simulator. The first run clones SwiftKeychainWrapper 4.0.1 into `ios/Tests/harness/.build`, so it needs network access once. The folder is git ignored. The clone lets the harness write legacy items with the same library upstream used. The script prints every failed check and the pass count, and exits non-zero when a check fails.

> **Warning**
> Up to upstream version v0.4.0 there was standard keychain used. Since v0.5.0 there is separate keychain wrapper, so keys() method returns only keys set in v0.5.0 or higher version.

### Android

Values live in the SharedPreferences file `cap_sec` (`MODE_PRIVATE`). Each value is encrypted with an AES-256-GCM key in AndroidKeyStore. `keys()` lists the entries of that file.

#### Storage format

A value is stored as the string `v2:` followed by base64 of the 12 byte IV, the ciphertext and the 16 byte GCM tag. The key alias is `<packageName>_cap_sec_aes_v2`, with purposes encrypt and decrypt, GCM, no padding and randomized encryption, so AndroidKeyStore picks a fresh IV for every write. The additional authenticated data is `v2:` plus the storage key, so an encrypted value copied to another key does not decrypt. The key is created on the first write and the plugin never deletes it, `clear()` empties the preferences file only.

Readers detect the format per entry, in this order:

1. starts with `v2:` → AES-GCM. The `:` is not in the base64 alphabet, so no older entry starts with it.
2. the RSA key pair of upstream versions (`<packageName>_cap_sec`) exists and the base64 decodes to a non-zero multiple of 256 bytes → RSA/ECB/PKCS1Padding in 256 byte blocks, as upstream wrote it.
3. the base64 decodes to valid UTF-8 → plaintext entry. Upstream fell back to plaintext base64 silently when AndroidKeyStore failed to initialise, so some installs have such entries.
4. anything else → unreadable.

When the RSA decrypt fails on a 256 byte multiple, step 3 still runs, because a plaintext value of exactly that length is possible. Undecryptable RSA output is random and practically never valid UTF-8.

#### Migration

An entry read through step 2 or 3 is encrypted with the AES key and written back with `commit()` before `get` resolves. On the first storage call of the process the plugin also walks the file on a background thread and migrates every older entry. The walk takes the storage lock per entry, so calls from JavaScript are not held up behind it, and an entry written by `set` in the meantime is left alone. When the AES key cannot be created or the write-back fails, `get` still returns the old value and the entry stays as it was until a later read or walk migrates it. The RSA key is kept for that reason, and the plugin never generates a new RSA key.

The upgrade needs nothing from the app. Users are not logged out and nothing is prompted.

#### Failure behaviour

- Reads fail open for older formats as described above.
- Writes fail closed. If the AES key cannot be created or used, `set` rejects with `error` and code `STORAGE_ERROR` and the previous entry stays untouched. The plugin never writes plaintext and never falls back to RSA.
- Keystore calls that fail with a transient error are retried up to three times (after 50 ms and 200 ms). Nothing is latched: the next call tries the keystore again, so a keystore that fails at startup does not degrade the whole process.
- An entry that exists but cannot be decrypted (a wrong GCM tag, a missing AES key, a failing RSA decrypt) rejects `get` with `Item with given key does not exist` and code `UNREADABLE`. The entry and the keys are not deleted, `set` overwrites the entry and `remove` deletes it. A missing key rejects with the same message and code `NOT_FOUND`. The messages are the same as upstream, only the codes are new.
- Undecryptable entries are expected after a device-to-device transfer that copied `cap_sec.xml` without the keystore key. Upstream read them as missing too.
- No keystore work happens in `load()`. The store is created on the first call, and all storage calls run in order on the plugin's own thread.

#### No lock-bound key flags

The AES key does not use `setUnlockedDeviceRequired`, `setUserAuthenticationRequired` or StrongBox:

- JavaScript keeps running in the background on Android, and the app reads values while the screen is locked, for example when the inactivity logout reloads the page after 20 minutes. A key bound to the unlocked state would fail those reads, and the app would treat the value as missing.
- On Android 12 to 14 keys with these flags have been reported to become permanently unusable on some devices, for example after lock screen changes. That would lose every stored value.

The key stays non-exportable inside AndroidKeyStore (hardware-backed where the device supports it), so a copy of `cap_sec.xml` alone does not reveal values.

#### Keep `cap_sec.xml` out of backups and transfers

`android:allowBackup="false"` does not stop device-to-device transfer on Android 12 and later. The copied file cannot be decrypted on the new device, because the key stays behind. Exclude the file in the app, not in the plugin.

`android/app/src/main/res/xml/data_extraction_rules.xml` (Android 12 and later):

```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="cap_sec.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="cap_sec.xml" />
    </device-transfer>
</data-extraction-rules>
```

`android/app/src/main/res/xml/backup_rules.xml` (Android 11 and earlier):

```xml
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <exclude domain="sharedpref" path="cap_sec.xml" />
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

`getDiagnostics()` resolves with counters of the current process: `migrated` (entries rewritten from RSA or plaintext), `lostItems` (distinct keys whose entry is intact but does not decrypt), `decryptFailures` (distinct keys in an unknown format or failing after all retries) and `keyBackend` (`keystoreAes`, `keystoreRsaLegacy` or `none`). `parked`, `duplicatesResolved` and `plaintextFallbacks` are always `0` and `accessGroupMode` is `n/a` on Android.

#### Never downgrade after the upgrade

Upstream versions and earlier builds of this fork cannot read `v2:` entries. After this version has written or migrated values, going back makes them unreadable.

#### Tests

```bash
cd android
./gradlew test                  # JVM tests of the format, reader order and migration
./gradlew connectedAndroidTest  # real AndroidKeyStore, needs a device or emulator
```

### Web

There is no secure storage in browser (not because it is not implemented by this plugin, but it does not exist at all). Values are stored in LocalStorage, but they are at least base64 encoded. Plugin adds 'cap_sec' prefix to keys to avoid conflicts with other data stored in LocalStorage.
