package com.whitestein.securestorage;

import android.content.Context;
import android.util.Log;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@CapacitorPlugin(name = "SecureStoragePlugin")
public class SecureStoragePluginPlugin extends Plugin {

    static final String LOG_TAG = "SecureStoragePlugin";

    static final String MESSAGE_NOT_FOUND = "Item with given key does not exist";
    static final String MESSAGE_ERROR = "error";
    static final String CODE_NOT_FOUND = "NOT_FOUND";
    static final String CODE_UNREADABLE = "UNREADABLE";
    static final String CODE_STORAGE_ERROR = "STORAGE_ERROR";

    /** One store per process, so all plugin instances share the lock, the sweep and the counters. */
    private static SecureStore sharedStore;

    /** Background executor of the legacy sweep, separate so it never delays calls from JavaScript. */
    private static final ExecutorService SWEEP_EXECUTOR = Executors.newSingleThreadExecutor((runnable) -> {
        Thread thread = new Thread(runnable, "SecureStoragePlugin-sweep");
        thread.setDaemon(true);
        return thread;
    });

    /** Runs storage calls in order and keeps keystore work off the Capacitor bridge thread. */
    private final ExecutorService executor = Executors.newSingleThreadExecutor((runnable) -> {
        Thread thread = new Thread(runnable, "SecureStoragePlugin");
        thread.setDaemon(true);
        return thread;
    });

    private Context context;
    private SecureStore store;

    @Override
    public void load() {
        super.load();
        // No keystore or disk work here, the store is created on first use.
        this.context = getContext().getApplicationContext();
    }

    /** Test hook: gives this instance its own store for the given context. */
    public void loadTextContext(Context context) {
        this.context = context.getApplicationContext();
        this.store = createStore(this.context);
    }

    private synchronized SecureStore store() {
        if (store == null) {
            synchronized (SecureStoragePluginPlugin.class) {
                if (sharedStore == null) {
                    sharedStore = createStore(context);
                }
                store = sharedStore;
            }
        }
        return store;
    }

    private static SecureStore createStore(Context context) {
        return new SecureStore(
            new SharedPreferencesKeyValueStore(context),
            new KeystoreCipherBackend(context.getPackageName()),
            Base64Codec.ANDROID,
            SWEEP_EXECUTOR,
            Thread::sleep,
            (message, error) -> Log.w(LOG_TAG, message + (error == null ? "" : ": " + error.getClass().getName()))
        );
    }

    @PluginMethod
    public void set(PluginCall call) {
        String key = call.getString("key");
        String value = call.getString("value");
        String finalValue = value == null ? "" : value;
        executor.execute(() -> {
            try {
                call.resolve(_set(key, finalValue));
            } catch (Exception e) {
                call.reject(MESSAGE_ERROR, CODE_STORAGE_ERROR, e);
            }
        });
    }

    @PluginMethod
    public void get(PluginCall call) {
        String key = call.getString("key");
        executor.execute(() -> {
            SecureStore.ReadResult result;
            try {
                result = store().get(key);
            } catch (Exception e) {
                Log.w(LOG_TAG, "get failed: " + e.getClass().getName());
                result = SecureStore.ReadResult.UNREADABLE;
            }
            switch (result.status) {
                case FOUND:
                    call.resolve(valueResult(new String(result.value, StandardCharsets.UTF_8)));
                    break;
                case NOT_FOUND:
                    call.reject(MESSAGE_NOT_FOUND, CODE_NOT_FOUND);
                    break;
                default:
                    call.reject(MESSAGE_NOT_FOUND, CODE_UNREADABLE);
                    break;
            }
        });
    }

    @PluginMethod
    public void keys(PluginCall call) {
        executor.execute(() -> {
            try {
                call.resolve(_keys());
            } catch (Exception e) {
                call.reject(MESSAGE_ERROR, CODE_STORAGE_ERROR, e);
            }
        });
    }

    @PluginMethod
    public void remove(PluginCall call) {
        String key = call.getString("key");
        executor.execute(() -> {
            try {
                if (store().contains(key)) {
                    call.resolve(_remove(key));
                } else {
                    call.reject(MESSAGE_NOT_FOUND, CODE_NOT_FOUND);
                }
            } catch (Exception e) {
                call.reject(MESSAGE_ERROR, CODE_STORAGE_ERROR, e);
            }
        });
    }

    @PluginMethod
    public void clear(PluginCall call) {
        executor.execute(() -> {
            try {
                call.resolve(_clear());
            } catch (Exception e) {
                call.reject(MESSAGE_ERROR, CODE_STORAGE_ERROR, e);
            }
        });
    }

    @PluginMethod
    public void getPlatform(PluginCall call) {
        call.resolve(_getPlatform());
    }

    /**
     * Counters of this process since the plugin loaded. Fields that only apply to iOS are always 0
     * or "n/a" on Android. lostItems and decryptFailures count distinct keys.
     */
    @PluginMethod
    public void getDiagnostics(PluginCall call) {
        executor.execute(() -> {
            try {
                call.resolve(_getDiagnostics());
            } catch (Exception e) {
                call.reject(MESSAGE_ERROR, CODE_STORAGE_ERROR, e);
            }
        });
    }

    public JSObject _set(String key, String value) throws Exception {
        store().set(key, value.getBytes(StandardCharsets.UTF_8));
        return booleanResult(true);
    }

    public boolean has(String key) {
        return store().get(key).status == SecureStore.Status.FOUND;
    }

    public JSObject _get(String key) throws Exception {
        SecureStore.ReadResult result = store().get(key);
        if (result.status != SecureStore.Status.FOUND) {
            throw new Exception(MESSAGE_NOT_FOUND);
        }
        return valueResult(new String(result.value, StandardCharsets.UTF_8));
    }

    public JSObject _keys() {
        JSObject ret = new JSObject();
        ret.put("value", JSArray.from(store().keys()));
        return ret;
    }

    public JSObject _remove(String key) {
        // The preferences keep the change in memory even when the disk write fails, so this
        // resolves like upstream did.
        store().remove(key);
        return booleanResult(true);
    }

    public JSObject _clear() {
        store().clear();
        return booleanResult(true);
    }

    public JSObject _getPlatform() {
        return valueResult("android");
    }

    public JSObject _getDiagnostics() {
        SecureStore.Diagnostics diagnostics = store().diagnostics();
        JSObject ret = new JSObject();
        ret.put("parked", 0);
        ret.put("migrated", diagnostics.migrated);
        ret.put("duplicatesResolved", 0);
        ret.put("lostItems", diagnostics.lostItems);
        ret.put("decryptFailures", diagnostics.decryptFailures);
        ret.put("plaintextFallbacks", 0);
        ret.put("keyBackend", diagnostics.keyBackend);
        ret.put("accessGroupMode", "n/a");
        return ret;
    }

    private static JSObject valueResult(String value) {
        JSObject ret = new JSObject();
        ret.put("value", value);
        return ret;
    }

    private static JSObject booleanResult(boolean value) {
        JSObject ret = new JSObject();
        ret.put("value", value);
        return ret;
    }
}
