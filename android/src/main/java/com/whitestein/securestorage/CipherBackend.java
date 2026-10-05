package com.whitestein.securestorage;

import java.security.GeneralSecurityException;

/**
 * Key material and cipher operations used by {@link SecureStore}. Production uses AndroidKeyStore
 * ({@link KeystoreCipherBackend}).
 *
 * <p>{@link SecureStore} classifies the exceptions. {@link javax.crypto.BadPaddingException}
 * (including {@link javax.crypto.AEADBadTagException}), {@link javax.crypto.IllegalBlockSizeException}
 * and {@link KeyUnavailableException} mean the blob can never be decrypted with the current key.
 * Anything else counts as transient and is retried.
 */
interface CipherBackend {
    /**
     * Encrypts with the AES-256-GCM key and creates the key when it does not exist yet.
     *
     * @return the 12 byte IV followed by the ciphertext and the 16 byte tag
     */
    byte[] aesEncrypt(byte[] plaintext, byte[] aad) throws GeneralSecurityException;

    /** Decrypts output of {@link #aesEncrypt}. Never creates a key. */
    byte[] aesDecrypt(byte[] ivAndCiphertext, byte[] aad) throws GeneralSecurityException;

    boolean hasAesKey() throws GeneralSecurityException;

    boolean hasRsaKey() throws GeneralSecurityException;

    /** Decrypts legacy RSA/ECB/PKCS1Padding ciphertext made of 256 byte blocks. Never creates a key. */
    byte[] rsaDecrypt(byte[] ciphertext) throws GeneralSecurityException;

    /** The key an operation needs does not exist. */
    final class KeyUnavailableException extends GeneralSecurityException {

        KeyUnavailableException(String message) {
            super(message);
        }
    }
}
