package uaic.security.demo;

/**
 * Everything the user chose for one demo run, still as typed.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 *
 * @param cipher         the cipher to configure
 * @param operation      encrypt or decrypt
 * @param key            the key, hex for byte ciphers and text for classical ones
 * @param nonceOrIv      the hex nonce (Salsa20, ChaCha20) or IV (block modes), or {@code null}
 * @param mode           the block mode, or {@code null} for non-block ciphers
 * @param input          the data, hex for byte ciphers and text for classical ones
 */
record CipherRequest(CipherName cipher, Operation operation, String key, String nonceOrIv, ModeName mode,
        String input) {
}
