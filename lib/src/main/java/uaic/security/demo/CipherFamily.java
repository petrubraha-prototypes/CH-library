package uaic.security.demo;

/**
 * Groups the demo ciphers by the settings they need: classical ciphers work
 * on text, stream ciphers may need a nonce and block ciphers need a mode.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
enum CipherFamily {
    CLASSICAL,
    STREAM,
    NONCE_STREAM,
    BLOCK;

    /**
     * @return the format of the key, the IV or nonce and the input
     */
    DataFormat dataFormat() {
        return this == CLASSICAL ? DataFormat.TEXT : DataFormat.HEX;
    }

    /**
     * @return whether the cipher is configured with a nonce
     */
    boolean requiresNonce() {
        return this == NONCE_STREAM;
    }

    /**
     * @return whether the cipher must be wrapped in a mode of operation
     */
    boolean requiresMode() {
        return this == BLOCK;
    }
}
