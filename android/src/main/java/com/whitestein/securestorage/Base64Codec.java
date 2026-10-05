package com.whitestein.securestorage;

/** Base64 behind an interface because android.util.Base64 is not available in JVM unit tests. */
interface Base64Codec {
    /** Encodes without line breaks. */
    String encode(byte[] data);

    /**
     * Decodes like android.util.Base64.DEFAULT: characters outside the alphabet, line breaks
     * included, are skipped. Throws IllegalArgumentException only for misplaced padding or an
     * incomplete final quantum, so callers check the alphabet themselves.
     */
    byte[] decode(String data);

    Base64Codec ANDROID = new Base64Codec() {
        @Override
        public String encode(byte[] data) {
            return android.util.Base64.encodeToString(data, android.util.Base64.NO_WRAP);
        }

        @Override
        public byte[] decode(String data) {
            return android.util.Base64.decode(data, android.util.Base64.DEFAULT);
        }
    };
}
