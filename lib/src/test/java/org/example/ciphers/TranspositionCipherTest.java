package org.example.ciphers;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TranspositionCipherTest {

    @Test
    void testBasicEncryptDecrypt() {
        TranspositionCipher cipher = new TranspositionCipher("SECRET");
        String message = "HELLOWORLD";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testWithSpacesAndSpecialChars() {
        TranspositionCipher cipher = new TranspositionCipher("KEY");
        String message = "Meet me at 12:00!";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testSingleCharacterKey() {
        TranspositionCipher cipher = new TranspositionCipher("A");
        String message = "SIMPLE";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }
}
