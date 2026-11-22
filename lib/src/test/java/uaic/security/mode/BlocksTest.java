package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

import uaic.security.util.Bytes;

class BlocksTest {

    @Test
    void splitKeepsAShorterLastBlock() {
        List<byte[]> blocks = Blocks.split(Bytes.fromHex("0102030405"), 2);
        assertEquals(3, blocks.size());
        assertArrayEquals(Bytes.fromHex("05"), blocks.get(2));
    }

    @Test
    void splitOfEmptyDataHasNoBlocks() {
        assertEquals(List.of(), Blocks.split(new byte[0], 4));
    }

    @Test
    void splitWholeRejectsAPartialBlock() {
        assertThrows(IllegalArgumentException.class, () -> Blocks.splitWhole(new byte[5], 4));
    }

    @Test
    void joinReversesSplit() {
        byte[] data = Bytes.fromHex("00112233445566");
        assertArrayEquals(data, Blocks.join(Blocks.split(data, 3)));
    }

    @Test
    void xorWithLeadingBytesUsesOnlyAsManyBytesAsTheSegment() {
        byte[] segment = Bytes.fromHex("ff00");
        byte[] outputBlock = Bytes.fromHex("0f0f0f0f");
        assertArrayEquals(Bytes.fromHex("f00f"), Blocks.xorWithLeadingBytes(segment, outputBlock));
    }

    @Test
    void requireOneBlockAcceptsExactlyOneBlock() {
        assertDoesNotThrow(() -> Blocks.requireOneBlock(new byte[4], 4, "IV"));
        assertThrows(IllegalArgumentException.class, () -> Blocks.requireOneBlock(new byte[3], 4, "IV"));
    }
}
