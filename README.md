[![npm version](https://badge.fury.io/js/better-capacitor-secure-storage-plugin.svg)](https://badge.fury.io/js/better-capacitor-secure-storage-plugin)

# better-capacitor-secure-storage-plugin

Capacitor plugin for storing string values securely on iOS and Android.

## Fork notice

This is a Skip Pay fork of [martinkasa/capacitor-secure-storage-plugin](https://github.com/martinkasa/capacitor-secure-storage-plugin), created to harden the Keychain/Keystore configuration after a penetration test. It keeps the same JavaScript API and the plugin name `SecureStoragePlugin`, so switching from upstream is an import change.

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

## Methods

```ts

get(options: { key: string }): Promise<{ value: string }>

```

> **Note**
> if item with specified key does not exist, throws an Error

---

```ts

set(options: { key: string; value: string }): Promise<{ value: boolean }>

```

> **Note**
> return true in case of success otherwise throws an error

---

```ts

remove(options: { key: string }): Promise<{ value: boolean }>

```

> **Note**
> return true in case of success otherwise throws an error

---

```ts
keys(): Promise<{ value: string[] }>
```

---

```ts

  clear(): Promise<{ value: boolean }>

```

> **Note**
> return true in case of success otherwise throws an error

---

```ts

getPlatform(): Promise<{ value: string }>

```

> **Note**
> return returns which implementation is used - one of 'web', 'ios' or 'android'

## Example

```ts
const key = 'username';
const value = 'hellokitty2';

SecureStoragePlugin.set({ key, value }).then((success) => console.log(success));
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

This plugin uses SwiftKeychainWrapper under the hood for iOS.

After reinstalling an app, the data stored in the keychain are not deleted automatically. To clear the data the following code has to be added to AppDelegate.swift. This is just an example, there are multiple ways how it can be achieved.

```swift
import SwiftKeychainWrapper


if !UserDefaults.standard.bool(forKey: "firstTimeLaunchOccurred") {
    let keychainWrapper = KeychainWrapper(serviceName: "cap_sec")
    keychainWrapper.removeAllKeys()

    UserDefaults.standard.set(true, forKey: "firstTimeLaunchOccurred")
}
```

> **Warning**
> Up to version v0.4.0 there was standard keychain used. Since v0.5.0 there is separate keychain wrapper, so keys() method returns only keys set in v0.5.0 or higher version.

### Android

On Android it is implemented by AndroidKeyStore and SharedPreferences. Source: [Apriorit](https://www.apriorit.com/dev-blog/432-using-androidkeystore)

> **Warning**
> For Android API < 18 values are stored as simple base64 encoded strings.

### Web

There is no secure storage in browser (not because it is not implemented by this plugin, but it does not exist at all). Values are stored in LocalStorage, but they are at least base64 encoded. Plugin adds 'cap_sec' prefix to keys to avoid conflicts with other data stored in LocalStorage.
