package com.whitestein.securestorage;

/** Base64 behind an interface because android.util.Base64 is not available in JVM unit tests. */
interface Base64Codec {
    /** Encodes without line breaks. */
    String encode(byte[] data);

    /** Decodes, ignoring line breaks. Throws IllegalArgumentException on invalid input. */
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
