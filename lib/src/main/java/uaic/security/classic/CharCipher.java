package uaic.security.classic;

/**
 * Character-level contract of the classical ciphers, which work on letters
 * rather than bytes. {@link TextCipherAdapter} exposes them as a
 * {@link uaic.security.Cipher}.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public interface CharCipher {
    /**
     * Encrypts the given plaintext.
     * 
     * @param plaintext the message to encrypt
     * @return the encrypted ciphertext
     */
    String encrypt(String plaintext);

    /**
     * Decrypts the given ciphertext.
     * 
     * @param ciphertext the message to decrypt
     * @return the decrypted plaintext
     */
    String decrypt(String ciphertext);
}
