package com.whitestein.securestorage;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Test doubles for {@link SecureStore}. The crypto is real JCE, only key storage is faked. */
final class Fakes {

    private Fakes() {}

    /** Encodes like android.util.Base64.NO_WRAP and decodes like android.util.Base64.DEFAULT. */
    static final Base64Codec BASE64 = new Base64Codec() {
        @Override
        public String encode(byte[] data) {
            return Base64.getEncoder().encodeToString(data);
        }

        @Override
        public byte[] decode(String data) {
            return androidDecode(data);
        }
    };

    /**
     * The decoder state machine of android.util.Base64.Decoder: characters outside the alphabet,
     * whitespace included, are skipped. It throws only for padding in the wrong place, characters
     * after the padding and an incomplete final quantum (one character, or two plus a single '=').
     */
    static byte[] androidDecode(String data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int state = 0;
        int value = 0;
        for (int i = 0; i < data.length(); i++) {
            int d = decodeValue(data.charAt(i));
            switch (state) {
                case 0:
                case 1:
                    if (d >= 0) {
                        value = (value << 6) | d;
                        state++;
                    } else if (d != SKIP) {
                        throw new IllegalArgumentException("bad base-64");
                    }
                    break;
                case 2:
                    if (d >= 0) {
                        value = (value << 6) | d;
                        state = 3;
                    } else if (d == EQUALS) {
                        out.write(value >> 4);
                        state = 4;
                    } else if (d != SKIP) {
                        throw new IllegalArgumentException("bad base-64");
                    }
                    break;
                case 3:
                    if (d >= 0) {
                        value = (value << 6) | d;
                        out.write(value >> 16);
                        out.write(value >> 8);
                        out.write(value);
                        value = 0;
                        state = 0;
                    } else if (d == EQUALS) {
                        out.write(value >> 10);
                        out.write(value >> 2);
                        state = 5;
                    } else if (d != SKIP) {
                        throw new IllegalArgumentException("bad base-64");
                    }
                    break;
                case 4:
                    if (d == EQUALS) {
                        state = 5;
                    } else if (d != SKIP) {
                        throw new IllegalArgumentException("bad base-64");
                    }
                    break;
                default:
                    if (d != SKIP) {
                        throw new IllegalArgumentException("bad base-64");
                    }
                    break;
            }
        }
        switch (state) {
            case 1:
            case 4:
                throw new IllegalArgumentException("bad base-64");
            case 2:
                out.write(value >> 4);
                break;
            case 3:
                out.write(value >> 10);
                out.write(value >> 2);
                break;
            default:
                break;
        }
        return out.toByteArray();
    }

    private static final int SKIP = -1;
    private static final int EQUALS = -2;

    private static int decodeValue(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        if (c == '=') {
            return EQUALS;
        }
        return SKIP;
    }

    /** Encodes like android.util.Base64.DEFAULT: 76 character lines and a trailing newline. */
    static String androidDefaultBase64(byte[] data) {
        if (data.length == 0) {
            return "";
        }
        return Base64.getMimeEncoder(76, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(data) + "\n";
    }

    static final class MapStore implements KeyValueStore {

        final Map<String, String> map = new HashMap<>();
        boolean failWrites = false;
        boolean failRemoves = false;
        boolean failClears = false;
        int writes = 0;
        int removes = 0;
        int clears = 0;
        int fileDeletions = 0;

        @Override
        public String getString(String key) {
            return map.get(key);
        }

        @Override
        public boolean contains(String key) {
            return map.containsKey(key);
        }

        @Override
        public Set<String> keys() {
            return new HashSet<>(map.keySet());
        }

        @Override
        public boolean putString(String key, String value) {
            writes++;
            if (failWrites) {
                return false;
            }
            map.put(key, value);
            return true;
        }

        @Override
        public boolean remove(String key) {
            removes++;
            if (failRemoves) {
                return false;
            }
            map.remove(key);
            return true;
        }

        @Override
        public boolean clear() {
            clears++;
            if (failClears) {
                return false;
            }
            map.clear();
            return true;
        }

        @Override
        public boolean deleteFile() {
            fileDeletions++;
            map.clear();
            return true;
        }
    }

    static final class FakeBackend implements CipherBackend {

        SecretKey aesKey;
        KeyPair rsaKey;
        /** When false, creating the AES key fails like a broken keystore would. */
        boolean aesCreatable = true;
        /** Number of upcoming calls (any method) that fail with a transient keystore error. */
        int transientFailures = 0;
        int aesEncryptCalls = 0;
        int aesKeysCreated = 0;
        int rsaKeysDeleted = 0;
        /** AAD of every aesEncrypt call that got past the failure hooks, in order. */
        final List<String> aesEncryptAads = new ArrayList<>();
        /** Thrown by upcoming aesEncrypt calls, one per call, before anything else happens. */
        final Deque<GeneralSecurityException> aesEncryptErrors = new ArrayDeque<>();
        /** Thrown by upcoming aesDecrypt calls, one per call, before anything else happens. */
        final Deque<GeneralSecurityException> aesDecryptErrors = new ArrayDeque<>();
        /** When set, every aesDecrypt call throws it. */
        GeneralSecurityException aesDecryptAlwaysThrows = null;
        /** When set, aesDecrypt with exactly this AAD throws AEADBadTagException. */
        byte[] aesDecryptBadTagForAad = null;
        /** When set, aesDecrypt with exactly this AAD returns its result with the first byte changed. */
        byte[] aesDecryptCorruptsForAad = null;
        /** Thrown by upcoming rsaDecrypt calls, one per call, before anything else happens. */
        final Deque<GeneralSecurityException> rsaDecryptErrors = new ArrayDeque<>();
        GeneralSecurityException deleteRsaKeyThrows = null;

        private final SecureRandom random = new SecureRandom();

        void createRsaKey() throws GeneralSecurityException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            rsaKey = generator.generateKeyPair();
        }

        /** Encrypts like upstream PasswordStorageHelper_SDK18: 245 byte chunks, base64 DEFAULT. */
        String upstreamRsaEncrypt(byte[] data) throws GeneralSecurityException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, rsaKey.getPublic());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int limit = 245;
            int position = 0;
            if (data.length == 0) {
                out.writeBytes(cipher.doFinal(data));
            }
            while (position < data.length) {
                int length = Math.min(limit, data.length - position);
                out.writeBytes(cipher.doFinal(data, position, length));
                position += length;
            }
            return androidDefaultBase64(out.toByteArray());
        }

        private void maybeFail() {
            if (transientFailures > 0) {
                transientFailures--;
                throw new ProviderException("Keystore operation failed");
            }
        }

        @Override
        public byte[] aesEncrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
            maybeFail();
            if (!aesEncryptErrors.isEmpty()) {
                throw aesEncryptErrors.poll();
            }
            aesEncryptCalls++;
            aesEncryptAads.add(new String(aad, StandardCharsets.UTF_8));
            if (aesKey == null) {
                if (!aesCreatable) {
                    throw new KeyStoreException("Could not generate key");
                }
                KeyGenerator generator = KeyGenerator.getInstance("AES");
                generator.init(256);
                aesKey = generator.generateKey();
                aesKeysCreated++;
            }
            byte[] iv = new byte[12];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.updateAAD(aad);
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] out = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
            return out;
        }

        @Override
        public byte[] aesDecrypt(byte[] blob, byte[] aad) throws GeneralSecurityException {
            maybeFail();
            if (!aesDecryptErrors.isEmpty()) {
                throw aesDecryptErrors.poll();
            }
            if (aesDecryptAlwaysThrows != null) {
                throw aesDecryptAlwaysThrows;
            }
            if (aesDecryptBadTagForAad != null && Arrays.equals(aesDecryptBadTagForAad, aad)) {
                throw new AEADBadTagException("Tag mismatch");
            }
            if (aesKey == null) {
                throw new KeyUnavailableException("AES key does not exist");
            }
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, blob, 0, 12));
            cipher.updateAAD(aad);
            byte[] plaintext = cipher.doFinal(blob, 12, blob.length - 12);
            if (aesDecryptCorruptsForAad != null && Arrays.equals(aesDecryptCorruptsForAad, aad) && plaintext.length > 0) {
                plaintext[0] ^= 1;
            }
            return plaintext;
        }

        @Override
        public boolean isTransientFailure(Throwable error) {
            for (Throwable current = error; current != null; current = current.getCause()) {
                if (current instanceof TransientKeystoreCause) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public boolean hasAesKey() {
            maybeFail();
            return aesKey != null;
        }

        @Override
        public boolean hasRsaKey() {
            maybeFail();
            return rsaKey != null;
        }

        @Override
        public byte[] rsaDecrypt(byte[] ciphertext) throws GeneralSecurityException {
            maybeFail();
            if (!rsaDecryptErrors.isEmpty()) {
                throw rsaDecryptErrors.poll();
            }
            if (rsaKey == null) {
                throw new KeyUnavailableException("RSA key does not exist");
            }
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, rsaKey.getPrivate());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (int position = 0; position < ciphertext.length; position += 256) {
                out.writeBytes(cipher.doFinal(ciphertext, position, 256));
            }
            return out.toByteArray();
        }

        @Override
        public void deleteRsaKey() throws GeneralSecurityException {
            maybeFail();
            if (deleteRsaKeyThrows != null) {
                throw deleteRsaKeyThrows;
            }
            rsaKey = null;
            rsaKeysDeleted++;
        }
    }

    /**
     * Stands in for android.security.KeyStoreException with isTransientFailure() true, which only
     * exists on Android 13 and later.
     */
    static final class TransientKeystoreCause extends Exception {

        TransientKeystoreCause() {
            super("Keystore busy");
        }
    }

    /** Wraps a transient key store cause the way AndroidKeyStore wraps it in doFinal. */
    static <T extends GeneralSecurityException> T withTransientCause(T error) {
        error.initCause(new TransientKeystoreCause());
        return error;
    }

    /** Collects submitted tasks so a test decides when the sweep runs. */
    static final class ManualExecutor implements Executor {

        final List<Runnable> tasks = new ArrayList<>();

        @Override
        public void execute(Runnable command) {
            tasks.add(command);
        }

        void runAll() {
            List<Runnable> pending = new ArrayList<>(tasks);
            tasks.clear();
            for (Runnable task : pending) {
                task.run();
            }
        }
    }

    static final class RecordingSleeper implements SecureStore.Sleeper {

        final List<Long> sleeps = new ArrayList<>();

        @Override
        public void sleep(long millis) {
            sleeps.add(millis);
        }
    }
}
