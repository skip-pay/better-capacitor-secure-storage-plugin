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

declare module '@capacitor/cli' {
  export interface PluginsConfig {
    /**
     * Configuration of better-capacitor-secure-storage-plugin.
     */
    SecureStoragePlugin?: {
      /**
       * Default keychain accessibility class for items written by the plugin (iOS only).
       * An unknown value makes every storage call reject with
       * `Unsupported accessibility value in plugin configuration`, only `getPlatform` still resolves.
       *
       * @since 1.0.0
       * @default 'afterFirstUnlock'
       * @example "whenUnlockedThisDeviceOnly"
       */
      accessibility?: KeychainAccessibility;
      /**
       * Encrypt stored values with a Secure Enclave key (iOS only).
       * Plaintext items in the plugin's `cap_sec` keychain service are encrypted when the plugin loads.
       * Items in the app bundle id service move into `cap_sec` and are encrypted lazily when `get` reads them.
       * A migrated item keeps its keychain class when that class is stricter than the configured default.
       * Android always encrypts with AndroidKeyStore, web ignores the option.
       *
       * @since 1.0.0
       * @default false
       * @example true
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
   * On iOS an encrypted item that cannot be decrypted rejects with `Item with given key could not be decrypted`.
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
}
