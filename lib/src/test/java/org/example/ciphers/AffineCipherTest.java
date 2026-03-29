package org.example.ciphers;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AffineCipherTest {

    @Test
    void testEncryptDecrypt() {
        AffineCipher cipher = new AffineCipher(5, 8);
        String message = "HELLOWORLD";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testWithSpacesAndCase() {
        AffineCipher cipher = new AffineCipher(5, 8);
        String message = "Hello World!";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testInvalidCoprime() {
        AffineCipher cipher = new AffineCipher(2, 8);
        String message = "HELLO";
        String encrypted = cipher.encrypt(message);
        assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(encrypted));
    }
}
