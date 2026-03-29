package org.example.ciphers;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SubstitutionCipherTest {

    @Test
    void testEncryptDecrypt() {
        String alphabet = "qwertyuiopasdfghjklzxcvbnm";
        SubstitutionCipher cipher = new SubstitutionCipher(alphabet);
        String message = "hello";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testWithCaseAndNonLetters() {
        String alphabet = "qwertyuiopasdfghjklzxcvbnm";
        SubstitutionCipher cipher = new SubstitutionCipher(alphabet);
        String message = "Hello, World!";
        String encrypted = cipher.encrypt(message);
        String decrypted = cipher.decrypt(encrypted);
        assertEquals(message, decrypted);
    }

    @Test
    void testInvalidAlphabetLength() {
        SubstitutionCipher cipher = new SubstitutionCipher("abc");
        assertThrows(IllegalArgumentException.class, () -> cipher.encrypt("hello"));
    }
}
