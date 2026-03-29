package org.example.ciphers;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class VigenereCipherTest {

    @Test
    void testStandardEncryptDecrypt() {
        VigenereCipher cipher = new VigenereCipher("KEYWORD");
        String message = "HELLOWORLD";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testMixedCaseAndNonLetters() {
        VigenereCipher cipher = new VigenereCipher("Key");
        String message = "Hello, World 2026!";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testEmptyKey() {
        VigenereCipher cipher = new VigenereCipher("");
        String message = "TEST";
        assertEquals(message, cipher.encrypt(message));
    }
}
