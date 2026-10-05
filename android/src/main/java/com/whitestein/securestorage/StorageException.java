package com.whitestein.securestorage;

/** A write could not be completed. Nothing was stored and a previous value stays in place. */
final class StorageException extends Exception {

    StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
