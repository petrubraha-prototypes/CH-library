package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import org.junit.jupiter.api.Test;

import uaic.security.util.Bytes;

class NoPaddingTest {

    private static final int BLOCK_SIZE = 4;
    private final Padding padding = new NoPadding();

    @Test
    void padLeavesTheDataUnchanged() {
        byte[] data = Bytes.fromHex("0102030405");
        assertArrayEquals(data, padding.pad(data, BLOCK_SIZE));
    }

    @Test
    void unpadLeavesTheDataUnchanged() {
        byte[] data = Bytes.fromHex("01020304");
        assertArrayEquals(data, padding.unpad(data, BLOCK_SIZE));
    }

    @Test
    void returnsACopy() {
        byte[] data = Bytes.fromHex("01020304");
        assertNotSame(data, padding.pad(data, BLOCK_SIZE));
        assertNotSame(data, padding.unpad(data, BLOCK_SIZE));
    }
}
