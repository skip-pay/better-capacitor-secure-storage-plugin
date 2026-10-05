package com.whitestein.securestorage;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Storage logic of the plugin, free of Android types so it runs in plain JVM tests.
 *
 * <p>Stored string formats, detected per entry in this order:
 *
 * <ol>
 *   <li>{@code "v2:" + base64(iv || ciphertext || tag)}: AES-256-GCM, AAD {@code "v2:" + key}.
 *       {@code ':'} is not in the base64 alphabet, so no legacy entry starts with the prefix.
 *   <li>base64 of RSA/ECB/PKCS1Padding blocks (upstream format), when the RSA key exists and the
 *       decoded length is a non-zero multiple of 256.
 *   <li>base64 of the UTF-8 value (upstream plaintext fallback when the keystore failed).
 * </ol>
 *
 * Reads fail open: a legacy value is returned even when it cannot be migrated. Writes fail
 * closed: only the v2 format is ever written, and a write that cannot be encrypted throws.
 *
 * <p>All public operations hold one lock, so the background sweep and calls from JavaScript never
 * interleave on the same entry.
 */
final class SecureStore {

    static final String V2_PREFIX = "v2:";
    static final int GCM_IV_BYTES = 12;
    static final int GCM_TAG_BYTES = 16;
    static final int RSA_BLOCK_BYTES = 256;

    /** Delays before the 2nd and 3rd attempt of a keystore operation that failed transiently. */
    static final long[] RETRY_DELAYS_MS = { 50, 200 };

    enum Status {
        FOUND,
        NOT_FOUND,
        /** The entry exists but cannot be decrypted. */
        UNREADABLE
    }

    static final class ReadResult {

        final Status status;
        final byte[] value;

        private ReadResult(Status status, byte[] value) {
            this.status = status;
            this.value = value;
        }

        static ReadResult found(byte[] value) {
            return new ReadResult(Status.FOUND, value);
        }

        static final ReadResult NOT_FOUND = new ReadResult(Status.NOT_FOUND, null);
        static final ReadResult UNREADABLE = new ReadResult(Status.UNREADABLE, null);
    }

    static final class Diagnostics {

        final int migrated;
        final int lostItems;
        final int decryptFailures;
        final String keyBackend;

        Diagnostics(int migrated, int lostItems, int decryptFailures, String keyBackend) {
            this.migrated = migrated;
            this.lostItems = lostItems;
            this.decryptFailures = decryptFailures;
            this.keyBackend = keyBackend;
        }
    }

    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    interface Logger {
        void warn(String message, Throwable error);

        Logger NONE = (message, error) -> {};
    }

    private interface KeystoreCall<T> {
        T run() throws Exception;
    }

    /** A keystore operation failed in a way retrying cannot fix. */
    private static final class PermanentFailure extends Exception {

        PermanentFailure(Throwable cause) {
            super(cause);
        }
    }

    private final KeyValueStore store;
    private final CipherBackend backend;
    private final Base64Codec base64;
    private final Executor sweepExecutor;
    private final Sleeper sleeper;
    private final Logger logger;

    private final AtomicBoolean sweepStarted = new AtomicBoolean(false);
    private final Set<String> lostKeys = new HashSet<>();
    private final Set<String> undecodableKeys = new HashSet<>();
    private int migrated = 0;

    SecureStore(KeyValueStore store, CipherBackend backend, Base64Codec base64, Executor sweepExecutor, Sleeper sleeper, Logger logger) {
        this.store = store;
        this.backend = backend;
        this.base64 = base64;
        this.sweepExecutor = sweepExecutor;
        this.sleeper = sleeper;
        this.logger = logger;
    }

    synchronized ReadResult get(String key) {
        startSweepOnce();
        return readAndMigrate(key);
    }

    /** Encrypts and stores a value. Throws without touching the stored entry when that fails. */
    synchronized void set(String key, byte[] value) throws StorageException {
        startSweepOnce();
        String encoded;
        try {
            encoded = encryptV2(key, value);
        } catch (Exception e) {
            throw new StorageException("Could not encrypt value", e);
        }
        if (!store.putString(key, encoded)) {
            throw new StorageException("Could not write value", null);
        }
    }

    synchronized boolean contains(String key) {
        startSweepOnce();
        return store.contains(key);
    }

    synchronized boolean remove(String key) {
        startSweepOnce();
        return store.remove(key);
    }

    /** Clears the preferences file. Keystore keys are kept. */
    synchronized boolean clear() {
        startSweepOnce();
        return store.clear();
    }

    synchronized String[] keys() {
        startSweepOnce();
        Set<String> keys = store.keys();
        return keys.toArray(new String[0]);
    }

    synchronized Diagnostics diagnostics() {
        String keyBackend;
        try {
            if (withRetry(backend::hasAesKey)) {
                keyBackend = "keystoreAes";
            } else if (withRetry(backend::hasRsaKey)) {
                keyBackend = "keystoreRsaLegacy";
            } else {
                keyBackend = "none";
            }
        } catch (Exception e) {
            keyBackend = "none";
        }
        return new Diagnostics(migrated, lostKeys.size(), undecodableKeys.size(), keyBackend);
    }

    /** Migrates every legacy entry. Runs on the sweep executor, takes the lock once per entry. */
    void sweepLegacyEntries() {
        Set<String> keys;
        synchronized (this) {
            keys = store.keys();
        }
        for (String key : keys) {
            synchronized (this) {
                String raw = readRaw(key);
                if (raw != null && !raw.startsWith(V2_PREFIX)) {
                    readAndMigrate(key);
                }
            }
        }
    }

    private void startSweepOnce() {
        if (sweepStarted.compareAndSet(false, true)) {
            try {
                sweepExecutor.execute(this::sweepLegacyEntries);
            } catch (RuntimeException e) {
                logger.warn("Could not start legacy sweep", e);
            }
        }
    }

    private String readRaw(String key) {
        try {
            return store.getString(key);
        } catch (ClassCastException e) {
            // Not a string, so not written by this plugin. Treat like an undecodable entry.
            return "";
        }
    }

    private ReadResult readAndMigrate(String key) {
        String raw;
        try {
            raw = store.getString(key);
        } catch (ClassCastException e) {
            return undecodable(key, e);
        }
        if (raw == null) {
            return ReadResult.NOT_FOUND;
        }
        if (raw.startsWith(V2_PREFIX)) {
            return readV2(key, raw);
        }
        ReadResult legacy = readLegacy(key, raw);
        if (legacy.status == Status.FOUND) {
            migrate(key, legacy.value);
        }
        return legacy;
    }

    private ReadResult readV2(String key, String raw) {
        byte[] blob;
        try {
            blob = base64.decode(raw.substring(V2_PREFIX.length()));
        } catch (IllegalArgumentException e) {
            return undecodable(key, e);
        }
        if (blob.length < GCM_IV_BYTES + GCM_TAG_BYTES) {
            return undecodable(key, null);
        }
        try {
            return ReadResult.found(withRetry(() -> backend.aesDecrypt(blob, aad(key))));
        } catch (PermanentFailure e) {
            return lost(key, e.getCause());
        } catch (Exception e) {
            return undecodable(key, e);
        }
    }

    private ReadResult readLegacy(String key, String raw) {
        byte[] bytes;
        try {
            bytes = base64.decode(raw);
        } catch (IllegalArgumentException e) {
            return undecodable(key, e);
        }
        Throwable rsaFailure = null;
        if (bytes.length > 0 && bytes.length % RSA_BLOCK_BYTES == 0) {
            boolean hasRsa;
            try {
                hasRsa = withRetry(backend::hasRsaKey);
            } catch (Exception e) {
                return undecodable(key, e);
            }
            if (hasRsa) {
                try {
                    return ReadResult.found(withRetry(() -> backend.rsaDecrypt(bytes)));
                } catch (PermanentFailure e) {
                    // Fall through: the bytes may still be a plaintext entry of 256 * n bytes.
                    // Undecryptable RSA output is random and practically never valid UTF-8.
                    rsaFailure = e.getCause();
                } catch (Exception e) {
                    return undecodable(key, e);
                }
            }
        }
        if (isValidUtf8(bytes)) {
            return ReadResult.found(bytes);
        }
        if (rsaFailure != null) {
            return lost(key, rsaFailure);
        }
        return undecodable(key, null);
    }

    /** Rewrites a legacy entry in the v2 format. A failure leaves the legacy entry in place. */
    private void migrate(String key, byte[] value) {
        try {
            String encoded = encryptV2(key, value);
            if (store.putString(key, encoded)) {
                migrated++;
            } else {
                logger.warn("Could not write migrated entry", null);
            }
        } catch (Exception e) {
            logger.warn("Could not migrate legacy entry, keeping it", e);
        }
    }

    private String encryptV2(String key, byte[] value) throws Exception {
        byte[] blob = withRetry(() -> backend.aesEncrypt(value, aad(key)));
        return V2_PREFIX + base64.encode(blob);
    }

    private ReadResult lost(String key, Throwable error) {
        logger.warn("Stored entry cannot be decrypted with the current key", error);
        lostKeys.add(key);
        return ReadResult.UNREADABLE;
    }

    private ReadResult undecodable(String key, Throwable error) {
        logger.warn("Stored entry could not be read", error);
        undecodableKeys.add(key);
        return ReadResult.UNREADABLE;
    }

    /**
     * Runs a keystore call up to {@code RETRY_DELAYS_MS.length + 1} times. A permanent failure is
     * thrown as {@link PermanentFailure} right away, the last transient failure is rethrown as is.
     */
    private <T> T withRetry(KeystoreCall<T> call) throws Exception {
        for (int attempt = 0; ; attempt++) {
            try {
                return call.run();
            } catch (Exception e) {
                if (isPermanent(e)) {
                    throw new PermanentFailure(e);
                }
                if (attempt >= RETRY_DELAYS_MS.length) {
                    throw e;
                }
                logger.warn("Keystore operation failed, retrying", e);
                try {
                    sleeper.sleep(RETRY_DELAYS_MS[attempt]);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    static boolean isPermanent(Throwable e) {
        return (
            e instanceof BadPaddingException || e instanceof IllegalBlockSizeException || e instanceof CipherBackend.KeyUnavailableException
        );
    }

    static byte[] aad(String key) {
        return (V2_PREFIX + key).getBytes(StandardCharsets.UTF_8);
    }

    static boolean isValidUtf8(byte[] bytes) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }
}
