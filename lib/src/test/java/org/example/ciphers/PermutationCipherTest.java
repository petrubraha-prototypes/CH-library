package org.example.ciphers;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PermutationCipherTest {

    @Test
    void testEncryptDecryptMultipleBlocks() {
        int[] key = { 2, 3, 0, 1 }; // Block size 4
        PermutationCipher cipher = new PermutationCipher(key);
        String message = "HELLOWORLD12"; // Length 12, multiple of 4
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testPartialBlockPadding() {
        int[] key = { 2, 0, 1 }; // Block size 3
        PermutationCipher cipher = new PermutationCipher(key);
        String message = "HELL"; // Length 4, requires padding in encryption
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
