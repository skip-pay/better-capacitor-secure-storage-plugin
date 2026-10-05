/// <reference types="@capacitor/cli" preserve="true" />

/**
 * Keychain accessibility class of a stored item on iOS.
 *
 * | Value                              | iOS constant                                        |
 * | ---------------------------------- | --------------------------------------------------- |
 * | `whenUnlocked`                     | `kSecAttrAccessibleWhenUnlocked`                    |
 * | `whenUnlockedThisDeviceOnly`       | `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`      |
 * | `afterFirstUnlock`                 | `kSecAttrAccessibleAfterFirstUnlock`                |
 * | `afterFirstUnlockThisDeviceOnly`   | `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`  |
 * | `whenPasscodeSetThisDeviceOnly`    | `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`   |
 *
 * Android and web accept the value and ignore it.
 */
export type KeychainAccessibility =
  | 'whenUnlocked'
  | 'whenUnlockedThisDeviceOnly'
  | 'afterFirstUnlock'
  | 'afterFirstUnlockThisDeviceOnly'
  | 'whenPasscodeSetThisDeviceOnly';

export interface SecureStorageSetOptions {
  /**
   * Key under which the value is stored.
   */
  key: string;
  /**
   * Value to store.
   */
  value: string;
  /**
   * Keychain accessibility class for this item (iOS only).
   * Overrides the `accessibility` plugin configuration for this call.
   * An unknown value rejects with `Unsupported accessibility value`.
   * Ignored on Android and web.
   *
   * @since 1.0.0
   */
  accessibility?: KeychainAccessibility;
}

/**
 * `code` of a rejected call on iOS. The rejection messages are the same as in upstream, the code only adds detail.
 *
 * | Code                        | Meaning                                                                                     |
 * | --------------------------- | ------------------------------------------------------------------------------------------- |
 * | `NOT_FOUND`                 | No item for the key.                                                                         |
 * | `UNREADABLE`                | An item exists but cannot be decrypted or read. The message says the key does not exist.   |
 * | `LOCKED`                    | Reserved. The plugin waits for unlock instead and does not emit it.                          |
 * | `UNSUPPORTED_ACCESSIBILITY` | Unknown `accessibility` value in the call or in the plugin configuration.                    |
 * | `STORAGE_ERROR`             | Any other keychain failure.                                                                  |
 *
 * @since 1.0.0
 */
export type SecureStorageErrorCode =
  | 'NOT_FOUND'
  | 'UNREADABLE'
  | 'LOCKED'
  | 'UNSUPPORTED_ACCESSIBILITY'
  | 'STORAGE_ERROR';

/**
 * State of the native storage for support and monitoring. Counters start at zero when the app process starts.
 *
 * @since 1.0.0
 */
export interface SecureStorageDiagnostics {
  /**
   * Calls that had to wait for protected data, for example because the device was locked.
   */
  parked: number;
  /**
   * Keys rewritten by a migration: moved into the app-private access group, re-encrypted or given a stricter class.
   */
  migrated: number;
  /**
   * Extra copies of a key deleted after the surviving copy was written and verified.
   */
  duplicatesResolved: number;
  /**
   * Calls whose item kept reporting a locked keychain while the device was unlocked and that were completed as if the item
   * were missing.
   */
  lostItems: number;
  /**
   * Reads of an item that could not be decrypted or decoded.
   */
  decryptFailures: number;
  /**
   * Values stored as plaintext with the strict class because encryption was unavailable.
   */
  plaintextFallbacks: number;
  /**
   * Key that encrypts values. `software` is the simulator fallback, `none` means no key exists yet or it could not be looked
   * up at this moment.
   */
  keyBackend: 'secureEnclave' | 'software' | 'none';
  /**
   * `explicit` when items live in the app-private `<team id>.<bundle id>` keychain access group, `default` when the plugin
   * fell back to the app's default access group or could not determine it yet.
   */
  accessGroupMode: 'explicit' | 'default';
}

declare module '@capacitor/cli' {
  export interface PluginsConfig {
    /**
     * Configuration of better-capacitor-secure-storage-plugin.
     */
    SecureStoragePlugin?: {
      /**
       * Default keychain accessibility class for items written by the plugin (iOS only).
       * `afterFirstUnlock` is available as an explicit opt-out, for example when the app must read values while the device is locked.
       * An unknown value makes every storage call reject with
       * `Unsupported accessibility value in plugin configuration`, only `getPlatform` still resolves.
       *
       * @since 1.0.0
       * @default 'whenUnlockedThisDeviceOnly'
       * @example "afterFirstUnlock"
       */
      accessibility?: KeychainAccessibility;
      /**
       * Encrypt stored values with a Secure Enclave key (iOS only). Enabled by default, set `false` to opt out.
       * Plaintext items in the plugin's `cap_sec` keychain service are encrypted by a sweep that runs once per app launch,
       * in the foreground, after the app's first call has completed (or about five seconds after load when the app makes no
       * call), and by the first `get` of the key.
       * Items in the app bundle id service move into `cap_sec` and are encrypted lazily when `get` reads them.
       * A migrated item keeps its keychain class when that class is stricter than the configured default.
       * Android always encrypts with AndroidKeyStore, web ignores the option.
       *
       * @since 1.0.0
       * @default true
       * @example false
       */
      encryptValues?: boolean;
    };
  }
}

export interface SecureStoragePluginPlugin {
  /**
   * Read a stored value.
   *
   * @param options The key to read.
   * @returns The stored value. Rejects with `Item with given key does not exist` when the key is missing.
   * On iOS an item that cannot be decrypted rejects with the same message and the code `UNREADABLE`, a `set` overwrites it.
   * While the device is locked the call waits for unlock instead of rejecting.
   */
  get(options: { key: string }): Promise<{ value: string }>;
  /**
   * Store a value under a key, replacing an existing one.
   *
   * @param options The key, the value and optionally the iOS keychain accessibility class.
   * @returns `true` on success, otherwise the promise rejects.
   */
  set(options: SecureStorageSetOptions): Promise<{ value: boolean }>;
  /**
   * Remove a stored value.
   *
   * @param options The key to remove.
   * @returns `true` on success. Rejects with `Item with given key does not exist` when the key is missing.
   */
  remove(options: { key: string }): Promise<{ value: boolean }>;
  /**
   * Remove all values in the plugin's keychain service plus the legacy bundle id copies of those keys.
   * On iOS legacy items left only in the bundle id service are kept and `get` can still return them.
   *
   * @returns `true` on success, otherwise the promise rejects.
   */
  clear(): Promise<{ value: boolean }>;
  /**
   * List the keys of all values in the plugin's keychain service.
   * On iOS legacy items in the bundle id service are not listed.
   *
   * @returns The stored keys.
   */
  keys(): Promise<{ value: string[] }>;
  /**
   * Get the implementation in use.
   *
   * @returns One of `web`, `ios` or `android`.
   */
  getPlatform(): Promise<{ value: string }>;
  /**
   * Read counters and the key and access group state of the native storage, for support and monitoring.
   * Resolves right away, also while other calls wait for the device to unlock.
   * Web resolves zeros with `keyBackend: 'none'` and `accessGroupMode: 'default'`. Android resolves zeros once its
   * implementation is in, a build without it rejects as not implemented.
   *
   * @since 1.0.0
   * @returns The diagnostics snapshot.
   */
  getDiagnostics(): Promise<SecureStorageDiagnostics>;
}
