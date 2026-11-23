package uaic.security.demo;

import lombok.RequiredArgsConstructor;

/**
 * The ciphers a demo user can pick, by the label typed on the command line.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@RequiredArgsConstructor
enum CipherName implements Choice {
    AFFINE("affine", CipherFamily.CLASSICAL),
    SUBSTITUTION("substitution", CipherFamily.CLASSICAL),
    PERMUTATION("permutation", CipherFamily.CLASSICAL),
    TRANSPOSITION("transposition", CipherFamily.CLASSICAL),
    VIGENERE("vigenere", CipherFamily.CLASSICAL),
    RC4("rc4", CipherFamily.STREAM),
    SALSA20("salsa20", CipherFamily.NONCE_STREAM),
    CHACHA20("chacha20", CipherFamily.NONCE_STREAM),
    DES("des", CipherFamily.BLOCK),
    TRIPLE_DES("3des", CipherFamily.BLOCK),
    AES128("aes128", CipherFamily.BLOCK);

    private final String label;
    private final CipherFamily family;

    @Override
    public String label() {
        return label;
    }

    /**
     * @return the settings this cipher needs
     */
    CipherFamily family() {
        return family;
    }
}
