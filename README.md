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
- iOS items live in the app-private keychain access group `<team id>.<bundle id>`, not in whatever group the app's entitlements make the default (often a group shared with extensions).
- Existing iOS items are migrated once per launch and on first read: moved into the app-private group, encrypted, given at least the configured class, and duplicate copies in other groups are collapsed into one: a copy this fork wrote, otherwise the copy upstream 0.13.0 read.
- iOS rejections carry a `code` in addition to the unchanged messages, and `getDiagnostics()` reports what the plugin did.
- Android encrypts with AES-256-GCM in AndroidKeyStore instead of chunked RSA, migrates RSA and plaintext entries, and rejects a write it cannot encrypt instead of storing it in plaintext.

The defaults on iOS are hardened: values are encrypted with a Secure Enclave key and stored with the `whenUnlockedThisDeviceOnly` class, so they are not available while the device is locked and do not leave the device in backups. Setting `encryptValues` to `false` and `accessibility` to `afterFirstUnlock` gives the upstream storage format and class, items still move into the app-private access group. On Android values are encrypted with an AES-256-GCM AndroidKeyStore key and older entries are migrated on read, see Android below. Web behaves as in upstream 0.13.0.

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

| Prop                | Type                                                                    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Default                                   | Since |
| ------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ----- |
| **`accessibility`** | <code><a href="#keychainaccessibility">KeychainAccessibility</a></code> | Default keychain accessibility class for items written by the plugin (iOS only). `afterFirstUnlock` is available as an explicit opt-out, for example when the app must read values while the device is locked. An unknown value makes every storage call reject with `Unsupported accessibility value in plugin configuration`, only `getPlatform` still resolves.                                                                                                                                                                                                                                                                                                      | <code>'whenUnlockedThisDeviceOnly'</code> | 1.0.0 |
| **`encryptValues`** | <code>boolean</code>                                                    | Encrypt stored values with a Secure Enclave key (iOS only). Enabled by default, set `false` to opt out. Plaintext items in the plugin's `cap_sec` keychain service are encrypted by a sweep that runs once per app launch, in the foreground, after the app's first call has completed (or about five seconds after load when the app makes no call), and by the first `get` of the key. Items in the app bundle id service move into `cap_sec` and are encrypted lazily when `get` reads them. A migrated item keeps its keychain class when that class is stricter than the configured default. Android always encrypts with AndroidKeyStore, web ignores the option. | <code>true</code>                         | 1.0.0 |

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

The class is applied on every write. A per-call `accessibility` on `set` wins over the configured default and stays on the item until the next `set`. Items written by upstream or an older build are tightened to at least the configured class by the migrations described under Migration below, which never loosen a class. Changing the configured class later affects new writes only. Android and web accept `accessibility` and ignore it, because Android already encrypts values with AndroidKeyStore and the browser has no keychain. `encryptValues` is iOS only.

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


### getDiagnostics()

```typescript
getDiagnostics() => Promise<SecureStorageDiagnostics>
```

Read counters and the key and access group state of the native storage, for support and monitoring.
Resolves right away, also while other calls wait for the device to unlock.
Web resolves zeros with `keyBackend: 'none'` and `accessGroupMode: 'default'`. Android resolves zeros once its
implementation is in, a build without it rejects as not implemented.

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

| Prop                     | Type                                                 | Description                                                                                                                                                                                                   |
| ------------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`parked`**             | <code>number</code>                                  | Calls that had to wait for protected data, for example because the device was locked.                                                                                                                         |
| **`migrated`**           | <code>number</code>                                  | Keys rewritten by a migration: moved into the app-private access group, re-encrypted or given a stricter class.                                                                                               |
| **`duplicatesResolved`** | <code>number</code>                                  | Extra copies of a key deleted after the surviving copy was written and verified.                                                                                                                              |
| **`lostItems`**          | <code>number</code>                                  | Calls whose item kept reporting a locked keychain while the device was unlocked and that were completed as if the item were missing.                                                                          |
| **`decryptFailures`**    | <code>number</code>                                  | Reads of an item that could not be decrypted or decoded.                                                                                                                                                      |
| **`plaintextFallbacks`** | <code>number</code>                                  | Values stored as plaintext with the strict class because encryption was unavailable.                                                                                                                          |
| **`keyBackend`**         | <code>'none' \| 'secureEnclave' \| 'software'</code> | Key that encrypts values. `software` is the simulator fallback, `none` means no key exists yet or it could not be looked up at this moment.                                                                   |
| **`accessGroupMode`**    | <code>'default' \| 'explicit'</code>                 | `explicit` when items live in the app-private `&lt;team id&gt;.&lt;bundle id&gt;` keychain access group, `default` when the plugin fell back to the app's default access group or could not determine it yet. |


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

Items are generic passwords in the keychain with service `cap_sec`. The key is stored in the account and generic attributes as UTF-8 data, items are not synchronizable, and items written by this fork carry the label `better-capacitor-secure-storage-plugin`. This is the shape SwiftKeychainWrapper used, so a query of upstream 0.13.0 still finds every item, whatever its access group.

#### Access group

The plugin keeps its items in the app-private access group `<team id>.<bundle id>`. At the first call it adds a throwaway item without a group, reads back the group the keychain chose, takes the team prefix before the first `.` and appends `Bundle.main.bundleIdentifier`. A second throwaway write into that group confirms the app may use it. Both items are deleted right away and the result is cached for the process.

The group matters when the app's entitlements list `keychain-access-groups`. The first entry becomes the default group for every write without an explicit group, and that entry is usually shared with an extension. In the Skip Pay app the default is the widget group, so upstream wrote items there from app 4.15 on. Items written before that sit in the app-ID group, and some keys have a copy in both.

New writes, the Secure Enclave key and migrations all use the app-private group. Reads search every group the app can access. When the throwaway items fail, the app has no team prefix or bundle id, or a later write into the group returns `errSecMissingEntitlement` (-34018) or `errSecParam`, the plugin logs it once and falls back to the default group for the rest of the process. `getDiagnostics()` reports `accessGroupMode: 'default'` in that case. A probe that hits a locked keychain is not cached, the call waits for unlock instead.

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
- `encryptValues: true` (default) stores the magic prefix `0x00 0x53 0x4B 0x01` followed by an ECIES ciphertext, algorithm `eciesEncryptionCofactorVariableIVX963SHA256AESGCM`. The key is a P-256 key in the Secure Enclave with the tag `capacitor-secure-storage-plugin.v1`, created in the app-private group with `.privateKeyUsage` and no other flag.
- The key class follows the configured item class. It is `whenUnlockedThisDeviceOnly` by default and with `whenUnlocked` or `whenPasscodeSetThisDeviceOnly`, and `afterFirstUnlockThisDeviceOnly` when the configuration asks for `afterFirstUnlock` or `afterFirstUnlockThisDeviceOnly`. The class is fixed when the key is created on first use. Changing the configuration later does not change an existing key.
- The plugin looks the key up in the app-private group first and then in every group, so a key created by an earlier build is reused and never duplicated. Only encryption creates a key, decryption never does, because a new key cannot open old ciphertext. Lookup and creation are serialised across the process. The plugin never deletes the key, `clear` included. On the simulator a software key is used when the Secure Enclave is not available.
- Readers accept both formats at all times, whatever `encryptValues` says.
- With `encryptValues` on, a class without `ThisDeviceOnly` gains nothing. The Secure Enclave key never leaves the device, so items restored from a backup onto another device cannot be decrypted there. See Unreadable and lost items below. Use a `ThisDeviceOnly` class together with encryption.

#### What the encryption protects against

Encryption with a Secure Enclave key defeats attacks that copy keychain data off the device or out of it: a keychain dump tool that prints item data, a backup, a forensic image read offline, and a device migration. They all get ciphertext only, and the private key cannot leave the Secure Enclave. Together with `whenUnlockedThisDeviceOnly` the items are also not in backups at all and are unreadable while the device is locked.

It does not stop code that runs on a jailbroken, unlocked device with access to the app's keychain group. A hook inside the app process, or a tool signed with the app's group or a wildcard group, can ask the Secure Enclave to decrypt exactly the way the plugin does. Jailbreak detection, runtime integrity checks and server-side limits on PIN attempts are the controls for that case, and this plugin provides none of them.

#### Migration

Every key is settled by one migration unit. It lists all copies of the key in `cap_sec` across every group the app can access, together with the copy in the app bundle id service. A copy that carries this fork's label wins over copies without it, and among labelled copies the newest modification date wins. When no copy carries the label, the winner is the copy upstream 0.13.0 returned: the plugin runs the 0.13.0 query (service, account and generic, not synchronizable, no access group, limit one) and takes the copy it finds. That is the value the app has been using, and the newest modification date can belong to a different copy. A bundle id copy only counts when `cap_sec` has none, whatever its date, and the same 0.13.0 query picks among bundle id copies. `getDiagnostics()` counts deleted or overwritten copies whose value differed from the winner in `conflictingDuplicates`. The unit then writes the winning value into the app-private group with the target class and the current encoding: an update when a copy already sits in that group, an add otherwise. It reads the written item back and decodes it. Only when that value matches does it delete every other copy, by persistent reference. A failed or unverified write deletes nothing, and the next run tries again.

The unit runs in two places.

- `get` settles its key inside the call, so the first read after an upgrade already returns the value 0.13.0 returned and never another copy left in a second group. A migration problem never fails the `get`, the value read is returned anyway. While protected data is known to be unavailable `get` only reads.
- A sweep settles every `cap_sec` key once per process. It runs whatever `encryptValues` says. It waits until the first app call of the process has completed, so on a cold start it never delays that call, or until about five seconds after load when the app makes no call. Then it runs once the queue of app calls has drained, in the foreground, and only once protected data is known to be available. Keys that are locked are skipped and the sweep runs again on a later drain, at most three times per launch.

`set` writes into the app-private group and then deletes the copies of that key in other groups and in the bundle id service.

When the winning copy cannot be decoded, the key reads as `UNREADABLE` and the unit deletes nothing, because promoting an older copy would bring back a stale value. On every `get` and sweep it encrypts and tightens each older copy that is readable plaintext in place instead. The rewrite keeps the copy's group and label, so the copy still ranks below the winner, and a rewrite that does not read back is put back. An older copy stays plaintext only when it is not readable as plaintext either (bytes that are not UTF-8), or when this fork wrote it next to an undecryptable copy it also wrote, because the rewrite would make it the newest labelled copy. Such a copy stays until the next `set` of the key deletes it.

Bundle id service items were written by upstream versions up to 0.4.0. The sweep only lists `cap_sec` keys, so a bundle id item of a key that has no `cap_sec` copy moves only on the first `get` of that key, and until then it stays plaintext with its old class. The sweep deletes a bundle id copy of a key that also exists in `cap_sec`. Bundle id items of other keys stay untouched, because other code in the app may own them. `remove` deletes the key in both services, `clear` deletes the bundle id copies of the keys it clears.

A migration never gives an item a looser class. For an item written by upstream or an older build the plugin combines the item's current class with the configured default and takes the stricter value on each of two axes. The unlock requirement goes from after first unlock to when unlocked to when a passcode is set. The device binding goes from migratable to `ThisDeviceOnly`. A current class the plugin does not know is replaced by the configured default. For example an upstream item with `afterFirstUnlock` becomes `whenUnlockedThisDeviceOnly` when that is the configured default, and a `whenUnlocked` item combined with a configured `afterFirstUnlockThisDeviceOnly` becomes `whenUnlockedThisDeviceOnly`. An item that carries this fork's label keeps the class its `set` chose, so a per-call `afterFirstUnlock` survives the sweep. A plain `set` always writes exactly the requested or the configured class.

With `encryptValues` off the migration still moves items into the app-private group, collapses duplicates and tightens legacy classes. It keeps plaintext as plaintext and encrypted items as they are.

#### Locked device

While the device is locked, keychain items with an unlock-bound class fail with `errSecInteractionNotAllowed` (-25308). A silent push, a background fetch or an over-the-air bundle that restarts the JavaScript can run the app in that state. Such calls are not reported as missing keys. They are queued strictly in order and wait for unlock. There is no absolute timeout. A call that is still locked stays at the head of the queue and everything behind it waits.

The plugin tracks protected data from `protectedDataWillBecomeUnavailable` and `protectedDataDidBecomeAvailable`. It also reads `UIApplication.isProtectedDataAvailable` on the main thread at load, on `willEnterForeground`, `didBecomeActive` and `didEnterBackground`, and on the retry timer below. The plugin queue never waits for the main thread, it reads a locked flag. Until the first read arrives the state counts as available and the keychain's own -25308 decides. When the configured default class is `whenUnlocked`, `whenUnlockedThisDeviceOnly` (the default) or `whenPasscodeSetThisDeviceOnly`, calls are held back while protected data is known to be unavailable, without touching the keychain. With `afterFirstUnlock` or `afterFirstUnlockThisDeviceOnly` calls run right away, and only a call that still gets -25308 is queued. An app that must read values while the device is locked has to opt out with `"accessibility": "afterFirstUnlock"`.

While any call waits, a one-second timer on the plugin's queue retries the queue and re-reads the protected-data state, so a missed notification cannot leave calls waiting after unlock. The timer stops when the queue is empty.

#### Unreadable and lost items

An item that decrypts to garbage, belongs to a Secure Enclave key that no longer exists, or holds bytes that are not UTF-8 rejects with `Item with given key does not exist` and the code `UNREADABLE`. The plugin deletes nothing in that case and a `set` overwrites the item. Before calling a decryption failure permanent the plugin checks that protected data is known to be available and that a throwaway write with the `whenUnlockedThisDeviceOnly` class succeeds. Otherwise it treats the failure as a locked device and the call waits.

A device migration such as Quick Start can carry `ThisDeviceOnly` items that stay visible but fail with -25308 forever, also on an unlocked device. A call stuck on such an item would wait forever. When a call returns -25308 while protected data is known to be available and the throwaway write succeeds, the plugin retries it on the next three timer ticks. If it is still refused, the plugin classifies the item as lost. `get` rejects with `Item with given key does not exist` and the code `UNREADABLE`, `remove` and `clear` delete what they can and resolve, `set` deletes every copy of the key and adds a fresh item, and `keys` resolves with an empty list. Retries only count once per tick and only while the throwaway write agrees, so a stale protected-data signal on a locked device never turns into a lost item.

#### Fallbacks

- When key generation or encryption fails for a reason other than a locked device, `set` stores the value as plaintext with at least the `whenUnlockedThisDeviceOnly` class instead of rejecting. The plugin logs a fault and counts it in `plaintextFallbacks`. A later sweep encrypts the item once encryption works again. A migration follows the same rule.
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
| `migrated`           | Keys a migration rewrote.                                                                             |
| `duplicatesResolved` | Extra copies deleted after the surviving copy was verified.                                           |
| `lostItems`          | Calls completed as lost after the retries.                                                            |
| `decryptFailures`    | Reads of an item that could not be decrypted or decoded.                                              |
| `plaintextFallbacks` | Values written as plaintext because encryption failed.                                                |
| `keyBackend`         | `secureEnclave`, `software` on the simulator, or `none` when no key exists or the lookup was refused. |
| `accessGroupMode`    | `explicit` for the app-private group, `default` after a fallback or before the group is known.        |

Web resolves zeros with `keyBackend: 'none'` and `accessGroupMode: 'default'`. Android reports `keyBackend` as `keystoreAes` or `keystoreRsaLegacy`, `accessGroupMode` as `n/a`, and `parked`, `duplicatesResolved` and `plaintextFallbacks` as zero.

#### Never downgrade after encryption was used

A build without this fork cannot read encrypted items. Its writes land in the default group next to the encrypted copy in the app-private group, and its reads may return either copy. Encryption is on by default, so do not switch back to upstream once this fork has written values with the defaults. If it happens anyway, upgrading again returns the value this fork wrote last, because a copy with the fork's label wins over the copies the older build added next to it. Values the older build wrote in the meantime are dropped. To stop encrypting, set `encryptValues` to `false`. New writes are plaintext again and the fork still reads the encrypted items that remain.

#### Tests

The iOS tests come in two parts.

The unit tests in `ios/Tests/SecureStoragePluginTests` cover configuration parsing, the accessibility mapping, the class combination rule for all 25 pairs, the locked-device queue, the retry timer, the lost-item escape, the sweep scheduling, the app-private group name, the rejection codes and `getDiagnostics`. They inject the protected-data signal, the unlock probe and the timer, and need no keychain. CI runs them. Set `SIMULATOR_ID` to the UDID of an available simulator (`xcrun simctl list devices available`) and run them from the repository root:

```bash
xcodebuild test -scheme BetterCapacitorSecureStoragePlugin -destination "id=$SIMULATOR_ID"
```

The keychain tests cannot run in the Swift package test bundle, because it has no keychain entitlement and every keychain call fails with -34018. They live in `ios/Tests/harness` as a small binary that is linked with embedded entitlements and spawned on a booted simulator:

```bash
ios/Tests/harness/build.sh
SIMULATOR_ID=<simulator udid> ios/Tests/harness/build.sh
```

Without `SIMULATOR_ID` the script uses the booted simulator. The first run clones SwiftKeychainWrapper 4.0.1 into `ios/Tests/harness/.build`, so it needs network access once. The folder is git ignored. The clone lets the harness write legacy items with the same library upstream used. The script prints every failed check and the pass count, and exits non-zero when a check fails.

`ios/Tests/harness/entitlements.plist` mirrors the app: a fake team prefix, the application identifier that the plugin turns into its app-private group, and one `keychain-access-groups` entry that acts as the shared default group. The harness covers copies in both groups with different modification dates, bundle id service items, mixed plaintext and encrypted items, undecryptable ciphertext, other services and an item without a service surviving `clear`, the fallback when the app-private group is not permitted, the never-loosens matrix, the key class, the plaintext fallback and lost items. It cannot simulate a locked device or a Quick Start migration, the unit tests cover that logic with injected signals.

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

## Releasing

Pushing a tag `vX.Y.Z` publishes the package to npm through `.github/workflows/release.yml`. The workflow first runs the CI checks (web build and lint, iOS unit tests and keychain harness, Android unit tests). Then it publishes with npm trusted publishing and a provenance attestation, and creates a GitHub release from the CHANGELOG section of the version.

1. Set the version: `npm version X.Y.Z --no-git-tag-version` updates `package.json` and `package-lock.json`.
2. In `CHANGELOG.md`, rename the `## X.Y.Z (unreleased)` heading to `## X.Y.Z`. The GitHub release notes are the lines under that heading.
3. Run `npm run release:check` and read the tarball list it prints.
4. Commit, tag and push the tag:

```bash
git commit -am "chore: release X.Y.Z"
git tag vX.Y.Z
git push origin master vX.Y.Z
```

The publish job fails when the tag is not `v` followed by the `package.json` version. Fix the version, move the tag and push it again.

### First publish and trusted publisher setup

npm can configure a trusted publisher only for a package that already exists. A maintainer therefore publishes the first version by hand. `prepublishOnly` builds `dist` first:

```bash
npm login
npm publish --access public
```

If the tag of that version is pushed afterwards, its publish job fails because the version is already on npm. That failure is expected once.

Then open the package on npmjs.com, go to Settings, Trusted publishing, and add GitHub Actions with these values:

- Organization or user: `skip-pay`
- Repository: `better-capacitor-secure-storage-plugin`
- Workflow filename: `release.yml` (file name only, case-sensitive)
- Environment: empty

Configurations created after 3 September 2026 allow only `npm stage publish` by default. Allow direct publishing with `npm publish` as well, because the workflow runs `npm publish`. npm does not validate the configuration when you save it, so a typo shows up only as a failed publish.

From then on every `v*` tag publishes on its own. The workflow uses no npm token. Trusted publishing needs a GitHub-hosted runner, npm 11.5.1 or later and Node 22.14.0 or later. The workflow installs the latest npm before it publishes. The `repository.url` in `package.json` has to point at this GitHub repository.
