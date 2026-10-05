package com.whitestein.securestorage;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.HashSet;
import java.util.Set;

final class SharedPreferencesKeyValueStore implements KeyValueStore {

    static final String PREFERENCES_FILE = "cap_sec";

    private final SharedPreferences preferences;

    SharedPreferencesKeyValueStore(Context context) {
        this.preferences = context.getSharedPreferences(PREFERENCES_FILE, Context.MODE_PRIVATE);
    }

    @Override
    public String getString(String key) {
        return preferences.getString(key, null);
    }

    @Override
    public boolean contains(String key) {
        return preferences.contains(key);
    }

    @Override
    public Set<String> keys() {
        return new HashSet<>(preferences.getAll().keySet());
    }

    @Override
    public boolean putString(String key, String value) {
        return preferences.edit().putString(key, value).commit();
    }

    @Override
    public boolean remove(String key) {
        return preferences.edit().remove(key).commit();
    }

    @Override
    public boolean clear() {
        return preferences.edit().clear().commit();
    }
}
