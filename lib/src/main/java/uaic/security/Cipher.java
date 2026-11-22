package uaic.security;

/**
 * The single public contract of the library: turns plaintext bytes into
 * ciphertext bytes and back.
 *
 * <p>
 * Classical ciphers, stream ciphers and block ciphers wrapped in a mode of
 * operation all implement it, so callers never depend on how a cipher works
 * inside.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public interface Cipher {
    /**
     * Encrypts the given plaintext.
     *
     * @param plaintext the message to encrypt
     * @return the ciphertext
     */
    byte[] encrypt(byte[] plaintext);

    /**
     * Decrypts the given ciphertext.
     *
     * @param ciphertext the message to decrypt
     * @return the recovered plaintext
     */
    byte[] decrypt(byte[] ciphertext);
}
