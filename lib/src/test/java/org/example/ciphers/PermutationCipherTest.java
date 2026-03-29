package org.example.ciphers;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PermutationCipherTest {

    @Test
    void testEncryptDecryptMultipleBlocks() {
        // Block size 4.
        int[] key = { 2, 3, 0, 1 };
        PermutationCipher cipher = new PermutationCipher(key);
        // Length 12, multiple of 4.
        String message = "HELLOWORLD12";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testPartialBlockPadding() {
        // Block size 3.
        int[] key = { 2, 0, 1 };
        PermutationCipher cipher = new PermutationCipher(key);
        // Length 4, requires padding in encryption.
        String message = "HELL";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testSingleCharacter() {
        int[] key = { 0 };
        PermutationCipher cipher = new PermutationCipher(key);
        String message = "A";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }
}
