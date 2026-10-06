package com.whitestein.securestorage;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * Storage logic of the plugin, free of Android types so it runs in plain JVM tests.
 *
 * <p>{@code store} holds only {@code "v2:" + base64(iv || ciphertext || tag)} entries: AES-256-GCM,
 * AAD {@code "v2:" + key}. {@code legacyStore} holds entries of older versions, detected per entry
 * in this order:
 *
 * <ol>
 *   <li>the v2 format, written into the legacy file by earlier builds of this fork. {@code ':'} is
 *       not in the base64 alphabet, so no other legacy entry starts with the prefix.
 *   <li>base64 of RSA/ECB/PKCS1Padding blocks (upstream format), when the RSA key exists and the
 *       decoded length is a non-zero multiple of 256.
 *   <li>base64 of the UTF-8 value (upstream plaintext fallback when the keystore failed).
 * </ol>
 *
 * Reads fail open: a legacy value is returned even when it cannot be migrated. Writes fail
 * closed: only the v2 format is ever written, and a write that cannot be encrypted throws.
 *
 * <p>A migration writes the v2 entry of a readable legacy entry only after the new v2 blob was
 * decrypted again and gave back the same bytes, and only once an AES round-trip self-test passed
 * in this process. Otherwise nothing is written and the legacy entry keeps being served. The legacy
 * entry is deleted only when {@code deleteLegacyStorage} is set.
 *
 * <p>All public operations hold one lock, so the background sweep and calls from JavaScript never
 * interleave on the same entry.
 */
final class SecureStore {

    // TODO(SS-12183): enable in the app version that follows the migration release, once most users have migrated
    static final boolean DELETE_LEGACY_STORAGE = false;

    static final String V2_PREFIX = "v2:";
    static final int GCM_IV_BYTES = 12;
    static final int GCM_TAG_BYTES = 16;
    static final int RSA_BLOCK_BYTES = 256;

    /** Delays before the 2nd and 3rd attempt of a keystore operation that failed transiently. */
    static final long[] RETRY_DELAYS_MS = { 50, 200 };

    /** Constant encrypted and decrypted by the self-test before the first migration write. */
    static final byte[] SELF_TEST_PLAINTEXT = "cap_sec AES self-test".getBytes(StandardCharsets.UTF_8);

    /** AAD of the self-test. It does not start with {@code "v2:"}, so it never equals {@link #aad}. */
    static final byte[] SELF_TEST_AAD = "self-test:v2".getBytes(StandardCharsets.UTF_8);

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
        /**
         * Distinct keys whose legacy entry is still stored after its migration was skipped. A key
         * is dropped once a migration or {@code set} wrote its v2 entry, or {@code remove}/{@code
         * clear} deleted it.
         */
        final int migrationSkipped;
        final int legacyEntriesKept;
        final String keyBackend;

        Diagnostics(int migrated, int lostItems, int decryptFailures, int migrationSkipped, int legacyEntriesKept, String keyBackend) {
            this.migrated = migrated;
            this.lostItems = lostItems;
            this.decryptFailures = decryptFailures;
            this.migrationSkipped = migrationSkipped;
            this.legacyEntriesKept = legacyEntriesKept;
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
    private final KeyValueStore legacyStore;
    private final boolean deleteLegacyStorage;
    private final CipherBackend backend;
    private final Base64Codec base64;
    private final Executor sweepExecutor;
    private final Sleeper sleeper;
    private final Logger logger;

    private final AtomicBoolean sweepStarted = new AtomicBoolean(false);
    private final Set<String> lostKeys = new HashSet<>();
    private final Set<String> undecodableKeys = new HashSet<>();
    private final Set<String> migrationSkippedKeys = new HashSet<>();
    private final Set<String> legacyEntriesKeptKeys = new HashSet<>();
    private int migrated = 0;
    private boolean legacyStorageDeleted = false;

    /**
     * Set once the AES round-trip self-test passed. There is one store per process in production,
     * so the test passes at most once per process. A failed test is not latched: the next migration
     * runs it again, so a keystore that recovers is used for migration again.
     */
    private boolean selfTestPassed = false;

    /** The last self-test run failed. */
    private boolean selfTestFailed = false;

    /**
     * An AES encrypt, the self-test or the check of a migrated blob failed after all its attempts,
     * and none of them succeeded since. While set, migrations and the sweep make a single attempt
     * per keystore operation without retry sleeps, so a broken keystore does not slow down every
     * legacy read. {@code set} always retries.
     */
    private boolean aesFailing = false;

    SecureStore(
        KeyValueStore store,
        KeyValueStore legacyStore,
        boolean deleteLegacyStorage,
        CipherBackend backend,
        Base64Codec base64,
        Executor sweepExecutor,
        Sleeper sleeper,
        Logger logger
    ) {
        this.store = store;
        this.legacyStore = legacyStore;
        this.deleteLegacyStorage = deleteLegacyStorage;
        this.backend = backend;
        this.base64 = base64;
        this.sweepExecutor = sweepExecutor;
        this.sleeper = sleeper;
        this.logger = logger;
    }

    synchronized ReadResult get(String key) {
        startSweepOnce();
        return read(key, true);
    }

    /**
     * Encrypts and stores a value. The ciphertext is decrypted once in memory first, so a keystore
     * that encrypts but cannot decrypt never replaces a readable entry with one nobody can read.
     * Throws without touching the stored entry when that fails.
     */
    synchronized void set(String key, byte[] value) throws StorageException {
        startSweepOnce();
        String encoded;
        try {
            encoded = encryptV2(key, value, true);
            byte[] storedBlob = base64.decode(encoded.substring(V2_PREFIX.length()));
            byte[] roundTrip = withRetry(() -> backend.aesDecrypt(storedBlob, aad(key)), this::isPermanentAes, true);
            if (!Arrays.equals(roundTrip, value)) {
                aesFailing = true;
                throw new StorageException("Encrypted value does not decrypt back to the same bytes", null);
            }
        } catch (StorageException e) {
            throw e;
        } catch (Exception e) {
            aesFailing = true;
            throw new StorageException("Could not encrypt value", e);
        }
        aesFailing = false;
        if (!store.putString(key, encoded)) {
            throw new StorageException("Could not write value", null);
        }
        migrationSkippedKeys.remove(key);
        if (deleteLegacyStorage) {
            removeLegacyEntry(key);
        }
    }

    synchronized boolean contains(String key) {
        startSweepOnce();
        return store.contains(key) || legacyStore.contains(key);
    }

    synchronized boolean remove(String key) {
        startSweepOnce();
        boolean removed = store.remove(key);
        return removeLegacyEntry(key) && removed;
    }

    /** Clears both preferences files. Keystore keys are kept. */
    synchronized boolean clear() {
        startSweepOnce();
        boolean cleared = store.clear();
        boolean legacyCleared = legacyStore.keys().isEmpty() || legacyStore.clear();
        if (legacyCleared) {
            migrationSkippedKeys.clear();
            legacyEntriesKeptKeys.clear();
            deleteLegacyStorageIfEmpty();
        }
        return cleared && legacyCleared;
    }

    synchronized String[] keys() {
        startSweepOnce();
        Set<String> keys = store.keys();
        keys.addAll(legacyStore.keys());
        return keys.toArray(new String[0]);
    }

    synchronized Diagnostics diagnostics() {
        String keyBackend;
        try {
            if (withRetry(backend::hasAesKey, this::isPermanentAes)) {
                keyBackend = "keystoreAes";
            } else if (withRetry(backend::hasRsaKey, this::isPermanentLegacy)) {
                keyBackend = "keystoreRsaLegacy";
            } else {
                keyBackend = "none";
            }
        } catch (Exception e) {
            keyBackend = "none";
        }
        return new Diagnostics(
            migrated,
            lostKeys.size(),
            undecodableKeys.size(),
            migrationSkippedKeys.size(),
            legacyEntriesKeptKeys.size(),
            keyBackend
        );
    }

    /**
     * Migrates every legacy entry that has no v2 entry yet. Runs on the sweep executor, takes the
     * lock once per entry. Stops when the self-test fails. Reads migrate the remaining entries.
     */
    void sweepLegacyEntries() {
        Set<String> keys;
        synchronized (this) {
            keys = legacyStore.keys();
        }
        for (String key : keys) {
            synchronized (this) {
                if (store.contains(key)) {
                    if (deleteLegacyStorage) {
                        read(key, !aesFailing);
                    }
                } else if (legacyStore.contains(key)) {
                    readLegacyAndMigrate(key, !aesFailing);
                    if (selfTestFailed) {
                        logger.warn("Legacy sweep stopped, AES self-test did not pass", null);
                        return;
                    }
                }
            }
        }
        synchronized (this) {
            deleteLegacyStorageIfEmpty();
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

    /**
     * Reads the v2 entry, or the legacy entry when there is no v2 entry, and migrates the legacy
     * entry. {@code retryReads} is false only for the sweep while {@link #aesFailing} is set.
     */
    private ReadResult read(String key, boolean retryReads) {
        String raw;
        try {
            raw = store.getString(key);
        } catch (ClassCastException e) {
            return undecodable(key, e);
        }
        if (raw == null) {
            return readLegacyAndMigrate(key, retryReads);
        }
        ReadResult result = raw.startsWith(V2_PREFIX) ? readV2(key, raw) : undecodable(key, null);
        if (result.status == Status.FOUND && deleteLegacyStorage) {
            removeLegacyEntry(key);
        }
        return result;
    }

    private ReadResult readLegacyAndMigrate(String key, boolean retryReads) {
        String raw;
        try {
            raw = legacyStore.getString(key);
        } catch (ClassCastException e) {
            return undecodable(key, e);
        }
        if (raw == null) {
            return ReadResult.NOT_FOUND;
        }
        ReadResult legacy = raw.startsWith(V2_PREFIX) ? readV2(key, raw) : readLegacy(key, raw, retryReads);
        if (legacy.status == Status.FOUND) {
            migrate(key, legacy.value);
        }
        return legacy;
    }

    private boolean removeLegacyEntry(String key) {
        boolean present = legacyStore.contains(key);
        if (present && !legacyStore.remove(key)) {
            logger.warn("Could not delete legacy entry", null);
            return false;
        }
        migrationSkippedKeys.remove(key);
        legacyEntriesKeptKeys.remove(key);
        if (present) {
            deleteLegacyStorageIfEmpty();
        }
        return true;
    }

    private void deleteLegacyStorageIfEmpty() {
        if (!deleteLegacyStorage || legacyStorageDeleted || !legacyStore.keys().isEmpty()) {
            return;
        }
        try {
            if (withRetry(backend::hasRsaKey, this::isPermanentLegacy)) {
                withRetry(
                    () -> {
                        backend.deleteRsaKey();
                        return null;
                    },
                    this::isPermanentLegacy
                );
            }
        } catch (Exception e) {
            logger.warn("Could not delete legacy RSA key", e);
            return;
        }
        if (legacyStore.deleteFile()) {
            legacyStorageDeleted = true;
        } else {
            logger.warn("Could not delete legacy preferences file", null);
        }
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
            return ReadResult.found(withRetry(() -> backend.aesDecrypt(blob, aad(key)), this::isPermanentAes));
        } catch (PermanentFailure e) {
            return lost(key, e.getCause());
        } catch (Exception e) {
            return undecodable(key, e);
        }
    }

    private ReadResult readLegacy(String key, String raw, boolean retry) {
        // android.util.Base64 skips characters outside the alphabet, so a corrupt entry would
        // decode to fewer bytes, or none, and read as a shorter value or "".
        if (!isBase64Text(raw)) {
            return undecodable(key, null);
        }
        byte[] bytes;
        try {
            bytes = base64.decode(raw);
        } catch (IllegalArgumentException e) {
            return undecodable(key, e);
        }
        if (bytes.length == 0 && !raw.isEmpty()) {
            return undecodable(key, null);
        }
        // Undecryptable RSA output is random and practically never valid UTF-8, so only bytes that
        // are valid UTF-8 can still be a plaintext entry when the RSA attempt fails.
        boolean plaintextCandidate = isValidUtf8(bytes);
        Throwable rsaFailure = null;
        if (bytes.length > 0 && bytes.length % RSA_BLOCK_BYTES == 0) {
            boolean hasRsa;
            try {
                hasRsa = withRetry(backend::hasRsaKey, this::isPermanentLegacy, retry);
            } catch (Exception e) {
                return keystoreReadFailed(key, e, retry);
            }
            if (hasRsa && !plaintextCandidate) {
                // No plaintext fall-through can help, so IllegalBlockSizeException, which
                // AndroidKeyStore uses for transient doFinal failures too, gets the retries.
                try {
                    return ReadResult.found(withRetry(() -> backend.rsaDecrypt(bytes), this::isPermanentRsa, retry));
                } catch (PermanentFailure e) {
                    return lost(key, e.getCause());
                } catch (Exception e) {
                    return keystoreReadFailed(key, e, retry);
                }
            }
            if (hasRsa) {
                try {
                    return ReadResult.found(withRetry(() -> backend.rsaDecrypt(bytes), this::isPermanentLegacy, retry));
                } catch (PermanentFailure e) {
                    // Fall through: the bytes may still be a plaintext entry of 256 * n bytes.
                    rsaFailure = e.getCause();
                } catch (Exception e) {
                    return keystoreReadFailed(key, e, retry);
                }
            }
        }
        if (plaintextCandidate) {
            return ReadResult.found(bytes);
        }
        if (rsaFailure != null) {
            return lost(key, rsaFailure);
        }
        return undecodable(key, null);
    }

    /**
     * A keystore call of the legacy reader failed. After a single attempt without retries, made only
     * by the sweep while {@link #aesFailing} is set, a failure that is not permanent may be
     * transient, so the key is not counted in {@code decryptFailures}: a later {@code get} retries.
     */
    private ReadResult keystoreReadFailed(String key, Exception error, boolean retried) {
        if (!retried && !(error instanceof PermanentFailure)) {
            logger.warn("Legacy entry not read in a single attempt, a later read retries", error);
            return ReadResult.UNREADABLE;
        }
        return undecodable(key, error);
    }

    /**
     * Writes the v2 entry of a legacy entry. The new blob is written only when it decrypts back to
     * the same bytes. Any failure counts the key as skipped until a later migration or write stores
     * its v2 entry. The legacy entry is never changed, it is only deleted after a v2 write when
     * {@link #deleteLegacyStorage} is set.
     */
    private void migrate(String key, byte[] value) {
        boolean retry = !aesFailing;
        if (!selfTest(retry)) {
            skipMigration(key, "AES self-test did not pass, keeping legacy entry", null);
            return;
        }
        String encoded;
        try {
            encoded = encryptV2(key, value, retry);
        } catch (Exception e) {
            skipMigration(key, "Could not migrate legacy entry, keeping it", e);
            return;
        }
        try {
            // Decode the string that would be stored, so the check covers the base64 step too.
            byte[] storedBlob = base64.decode(encoded.substring(V2_PREFIX.length()));
            byte[] roundTrip = withRetry(() -> backend.aesDecrypt(storedBlob, aad(key)), this::isPermanentAes, retry);
            if (!Arrays.equals(roundTrip, value)) {
                aesFailing = true;
                skipMigration(key, "Migrated entry decrypts to a different value, keeping legacy entry", null);
                return;
            }
        } catch (Exception e) {
            aesFailing = true;
            skipMigration(key, "Migrated entry does not decrypt, keeping legacy entry", e);
            return;
        }
        aesFailing = false;
        if (store.putString(key, encoded)) {
            migrated++;
            migrationSkippedKeys.remove(key);
            if (!deleteLegacyStorage || !removeLegacyEntry(key)) {
                legacyEntriesKeptKeys.add(key);
            }
        } else {
            skipMigration(key, "Could not write migrated entry", null);
        }
    }

    /**
     * Encrypts and decrypts a constant with a fixed AAD. Runs before the first migration write of
     * the process and again before later migrations until it passes once.
     */
    private boolean selfTest(boolean retry) {
        if (selfTestPassed) {
            return true;
        }
        try {
            byte[] blob = withRetry(() -> backend.aesEncrypt(SELF_TEST_PLAINTEXT, SELF_TEST_AAD), this::isPermanentAes, retry);
            byte[] roundTrip = withRetry(() -> backend.aesDecrypt(blob, SELF_TEST_AAD), this::isPermanentAes, retry);
            if (Arrays.equals(roundTrip, SELF_TEST_PLAINTEXT)) {
                selfTestPassed = true;
                selfTestFailed = false;
                aesFailing = false;
                return true;
            }
            logger.warn("AES self-test decrypted to a different value", null);
        } catch (Exception e) {
            logger.warn("AES self-test failed", e);
        }
        selfTestFailed = true;
        aesFailing = true;
        return false;
    }

    private void skipMigration(String key, String message, Throwable error) {
        logger.warn(message, error);
        migrationSkippedKeys.add(key);
    }

    /** Encrypts in the v2 format. A failure sets {@link #aesFailing}, callers clear it on success. */
    private String encryptV2(String key, byte[] value, boolean retry) throws Exception {
        byte[] blob;
        try {
            blob = withRetry(() -> backend.aesEncrypt(value, aad(key)), this::isPermanentAes, retry);
        } catch (Exception e) {
            aesFailing = true;
            throw e;
        }
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
     * Runs a keystore call up to {@code RETRY_DELAYS_MS.length + 1} times. A failure {@code
     * permanent} accepts is thrown as {@link PermanentFailure} right away. The last transient
     * failure is rethrown as is.
     */
    private <T> T withRetry(KeystoreCall<T> call, Predicate<Throwable> permanent) throws Exception {
        return withRetry(call, permanent, true);
    }

    /** Like {@link #withRetry(KeystoreCall, Predicate)}, but makes a single attempt when {@code retry} is false. */
    private <T> T withRetry(KeystoreCall<T> call, Predicate<Throwable> permanent, boolean retry) throws Exception {
        int retries = retry ? RETRY_DELAYS_MS.length : 0;
        for (int attempt = 0; ; attempt++) {
            try {
                return call.run();
            } catch (Exception e) {
                if (permanent.test(e)) {
                    throw new PermanentFailure(e);
                }
                if (attempt >= retries) {
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

    /**
     * AES-GCM path. Only a wrong tag and a missing key are permanent. AndroidKeyStore reports most
     * other doFinal failures as IllegalBlockSizeException, so that and a plain BadPaddingException
     * are retried and end as an unreadable read, never as a lost item.
     */
    private boolean isPermanentAes(Throwable e) {
        return !backend.isTransientFailure(e) && isPermanentAesType(e);
    }

    /**
     * Legacy RSA path for bytes that are valid UTF-8. BadPaddingException and
     * IllegalBlockSizeException stay permanent, so a 256 byte multiple that is really a plaintext
     * entry falls through to the UTF-8 reader without retry delays.
     */
    private boolean isPermanentLegacy(Throwable e) {
        return !backend.isTransientFailure(e) && isPermanentLegacyType(e);
    }

    /**
     * Legacy RSA path for bytes that are not valid UTF-8, so they can only be RSA ciphertext. Only
     * BadPaddingException and a missing key are permanent. IllegalBlockSizeException is retried
     * like on the AES path and ends as an unreadable read, never as a lost item.
     */
    private boolean isPermanentRsa(Throwable e) {
        return !backend.isTransientFailure(e) && isPermanentRsaType(e);
    }

    static boolean isPermanentAesType(Throwable e) {
        return e instanceof AEADBadTagException || e instanceof CipherBackend.KeyUnavailableException;
    }

    static boolean isPermanentLegacyType(Throwable e) {
        return (
            e instanceof BadPaddingException || e instanceof IllegalBlockSizeException || e instanceof CipherBackend.KeyUnavailableException
        );
    }

    static boolean isPermanentRsaType(Throwable e) {
        return e instanceof BadPaddingException || e instanceof CipherBackend.KeyUnavailableException;
    }

    static byte[] aad(String key) {
        return (V2_PREFIX + key).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * True when every character matches {@code [A-Za-z0-9+/=\s]}, with {@code \s} as in {@link
     * java.util.regex.Pattern}: space, tab, line feed, vertical tab, form feed, carriage return.
     */
    static boolean isBase64Text(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean alphabet =
                (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
            boolean whitespace = c == ' ' || c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r';
            if (!alphabet && !whitespace) {
                return false;
            }
        }
        return true;
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
