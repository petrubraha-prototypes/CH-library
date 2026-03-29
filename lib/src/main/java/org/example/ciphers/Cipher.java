package org.example.ciphers;

/**
 * Base interface for all cipher implementations.
 */
public interface Cipher {
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
