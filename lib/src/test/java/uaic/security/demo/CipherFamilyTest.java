package uaic.security.demo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CipherFamilyTest {

    @Test
    void onlyClassicalCiphersUseText() {
        assertEquals(DataFormat.TEXT, CipherFamily.CLASSICAL.dataFormat());
        assertEquals(DataFormat.HEX, CipherFamily.STREAM.dataFormat());
        assertEquals(DataFormat.HEX, CipherFamily.NONCE_STREAM.dataFormat());
        assertEquals(DataFormat.HEX, CipherFamily.BLOCK.dataFormat());
    }

    @Test
    void onlyNonceStreamCiphersNeedANonce() {
        assertTrue(CipherFamily.NONCE_STREAM.requiresNonce());
        assertFalse(CipherFamily.STREAM.requiresNonce());
        assertFalse(CipherFamily.BLOCK.requiresNonce());
    }

    @Test
    void onlyBlockCiphersNeedAMode() {
        assertTrue(CipherFamily.BLOCK.requiresMode());
        assertFalse(CipherFamily.CLASSICAL.requiresMode());
        assertFalse(CipherFamily.NONCE_STREAM.requiresMode());
    }
}
