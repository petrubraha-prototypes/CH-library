package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

import uaic.security.Cipher;

class OperationTest {

    /** Marks which method was called by prefixing 'e' or 'd'. */
    private static final Cipher MARKING_CIPHER = new Cipher() {
        @Override
        public byte[] encrypt(byte[] plaintext) {
            return new byte[] { 'e', plaintext[0] };
        }

        @Override
        public byte[] decrypt(byte[] ciphertext) {
            return new byte[] { 'd', ciphertext[0] };
        }
    };

    @Test
    void encryptCallsEncrypt() {
        assertArrayEquals(new byte[] { 'e', 1 }, Operation.ENCRYPT.apply(MARKING_CIPHER, new byte[] { 1 }));
    }

    @Test
    void decryptCallsDecrypt() {
        assertArrayEquals(new byte[] { 'd', 1 }, Operation.DECRYPT.apply(MARKING_CIPHER, new byte[] { 1 }));
    }
}
