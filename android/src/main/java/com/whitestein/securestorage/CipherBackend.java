package com.whitestein.securestorage;

import java.security.GeneralSecurityException;

/**
 * Key material and cipher operations used by {@link SecureStore}. Production uses AndroidKeyStore
 * ({@link KeystoreCipherBackend}).
 *
 * <p>{@link SecureStore} classifies the exceptions per path. On the AES path only {@link
 * javax.crypto.AEADBadTagException} and {@link KeyUnavailableException} mean the blob can never be
 * decrypted with the current key. AndroidKeyStore reports most other {@code doFinal} failures as
 * {@link javax.crypto.IllegalBlockSizeException}, so that and a plain {@link
 * javax.crypto.BadPaddingException} are retried there. On the legacy RSA path {@link
 * javax.crypto.BadPaddingException} and {@link KeyUnavailableException} are permanent, and {@link
 * javax.crypto.IllegalBlockSizeException} is permanent only when the stored bytes are valid UTF-8
 * and can still be read as a plaintext entry. Anything else counts as transient and is retried, and
 * so does any exception for which {@link #isTransientFailure} returns true.
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

    void deleteRsaKey() throws GeneralSecurityException;

    /**
     * True when the key store itself reports the failure behind {@code error} as transient, which
     * overrides the permanent classification of the exception type.
     */
    default boolean isTransientFailure(Throwable error) {
        return false;
    }

    /** The key an operation needs does not exist. */
    final class KeyUnavailableException extends GeneralSecurityException {

        KeyUnavailableException(String message) {
            super(message);
        }
    }
}
