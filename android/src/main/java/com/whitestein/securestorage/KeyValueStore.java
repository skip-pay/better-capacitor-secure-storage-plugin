package com.whitestein.securestorage;

import java.util.Set;

/** Raw string storage behind {@link SecureStore}. Production uses SharedPreferences. */
interface KeyValueStore {
    String getString(String key);

    boolean contains(String key);

    Set<String> keys();

    /** Writes synchronously. Returns false when the write did not reach disk. */
    boolean putString(String key, String value);

    boolean remove(String key);

    boolean clear();

    boolean deleteFile();
}
