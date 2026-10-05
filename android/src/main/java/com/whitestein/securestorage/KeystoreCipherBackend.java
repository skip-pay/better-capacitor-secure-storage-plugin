package com.whitestein.securestorage;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.annotation.RequiresApi;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AndroidKeyStore implementation of {@link CipherBackend}.
 *
 * <p>Nothing is latched: every call opens the keystore again, so a keystore that failed once is
 * tried again on the next operation. No lock-bound flags are set on the AES key (no user
 * authentication, no unlocked-device requirement, no StrongBox), because the app reads values
 * from background JavaScript while the screen is locked.
 */
final class KeystoreCipherBackend implements CipherBackend {

    static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    static final int GCM_IV_BYTES = 12;
    static final int GCM_TAG_BITS = 128;
    static final int RSA_BLOCK_BYTES = 256;

    private final String aesAlias;
    private final String rsaAlias;

    KeystoreCipherBackend(String packageName) {
        this.aesAlias = aesAlias(packageName);
        this.rsaAlias = rsaAlias(packageName);
    }

    static String aesAlias(String packageName) {
        return packageName + "_cap_sec_aes_v2";
    }

    /** Alias of the RSA key pair written by upstream versions. Read only, never generated. */
    static String rsaAlias(String packageName) {
        return packageName + "_cap_sec";
    }

    @Override
    public synchronized byte[] aesEncrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException {
        SecretKey key = getOrCreateAesKey();
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        // No IV passed: the keystore generates a random one (randomized encryption is required).
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] iv = cipher.getIV();
        if (iv == null || iv.length != GCM_IV_BYTES) {
            throw new GeneralSecurityException("Unexpected GCM IV length");
        }
        byte[] out = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
        return out;
    }

    @Override
    public synchronized byte[] aesDecrypt(byte[] ivAndCiphertext, byte[] aad) throws GeneralSecurityException {
        KeyStore keyStore = openKeyStore();
        Key key = keyStore.getKey(aesAlias, null);
        if (!(key instanceof SecretKey)) {
            throw new KeyUnavailableException("AES key does not exist");
        }
        Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, ivAndCiphertext, 0, GCM_IV_BYTES));
        cipher.updateAAD(aad);
        return cipher.doFinal(ivAndCiphertext, GCM_IV_BYTES, ivAndCiphertext.length - GCM_IV_BYTES);
    }

    @Override
    public synchronized boolean hasAesKey() throws GeneralSecurityException {
        return openKeyStore().containsAlias(aesAlias);
    }

    @Override
    public synchronized boolean hasRsaKey() throws GeneralSecurityException {
        return openKeyStore().containsAlias(rsaAlias);
    }

    @Override
    public synchronized byte[] rsaDecrypt(byte[] ciphertext) throws GeneralSecurityException {
        Key key = openKeyStore().getKey(rsaAlias, null);
        if (!(key instanceof PrivateKey)) {
            throw new KeyUnavailableException("RSA key does not exist");
        }
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int position = 0; position < ciphertext.length; position += RSA_BLOCK_BYTES) {
            int length = Math.min(RSA_BLOCK_BYTES, ciphertext.length - position);
            byte[] block = cipher.doFinal(ciphertext, position, length);
            out.write(block, 0, block.length);
        }
        return out.toByteArray();
    }

    /**
     * On Android 13 and later AndroidKeyStore attaches an {@link android.security.KeyStoreException}
     * as the cause of a failed operation, and that exception says whether retrying can help.
     */
    @Override
    public boolean isTransientFailure(Throwable error) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return false;
        }
        return Api33.hasTransientKeyStoreCause(error);
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private static final class Api33 {

        /** Causes followed at most, guards against cyclic cause chains. */
        private static final int MAX_CAUSE_DEPTH = 8;

        static boolean hasTransientKeyStoreCause(Throwable error) {
            Throwable current = error;
            for (int depth = 0; current != null && depth < MAX_CAUSE_DEPTH; depth++) {
                if (
                    current instanceof android.security.KeyStoreException &&
                    ((android.security.KeyStoreException) current).isTransientFailure()
                ) {
                    return true;
                }
                current = current.getCause();
            }
            return false;
        }
    }

    private SecretKey getOrCreateAesKey() throws GeneralSecurityException {
        KeyStore keyStore = openKeyStore();
        Key existing = keyStore.getKey(aesAlias, null);
        if (existing instanceof SecretKey) {
            return (SecretKey) existing;
        }
        if (keyStore.containsAlias(aesAlias)) {
            // Never replace an alias that exists but could not be loaded right now. That would make
            // every stored value unreadable. Fail this write. The next one tries again.
            throw new KeyStoreException("AES key exists but could not be loaded");
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        generator.init(
            new KeyGenParameterSpec.Builder(aesAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        );
        return generator.generateKey();
    }

    private static KeyStore openKeyStore() throws GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        try {
            keyStore.load(null);
        } catch (IOException e) {
            throw new KeyStoreException("Could not load AndroidKeyStore", e);
        }
        return keyStore;
    }
}
