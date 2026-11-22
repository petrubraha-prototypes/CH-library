package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class CipherNameTest {

    @Test
    void labelsMatchTheCommandLineNames() {
        assertEquals("affine, substitution, permutation, transposition, vigenere, rc4, salsa20, chacha20, des,"
                + " 3des, aes128", Choice.describe(CipherName.values()));
    }

    @Test
    void familiesGroupTheCiphers() {
        assertEquals(CipherFamily.CLASSICAL, CipherName.VIGENERE.family());
        assertEquals(CipherFamily.STREAM, CipherName.RC4.family());
        assertEquals(CipherFamily.NONCE_STREAM, CipherName.CHACHA20.family());
        assertEquals(CipherFamily.BLOCK, CipherName.TRIPLE_DES.family());
    }
}
