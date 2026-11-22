package uaic.security.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import uaic.security.util.Bytes;

class XorCombinerTest {

    private static Keystream constantKeystream(byte value) {
        return () -> value;
    }

    @Test
    void combineXorsEachByteWithTheKeystream() {
        byte[] data = Bytes.fromHex("00ff0f");
        byte[] combined = XorCombiner.combine(data, constantKeystream((byte) 0xf0));
        assertArrayEquals(Bytes.fromHex("f00fff"), combined);
    }

    @Test
    void combiningTwiceWithTheSameKeystreamRestoresTheData() {
        byte[] data = Bytes.fromHex("48656c6c6f");
        byte[] once = XorCombiner.combine(data, constantKeystream((byte) 0x5a));
        byte[] twice = XorCombiner.combine(once, constantKeystream((byte) 0x5a));
        assertArrayEquals(data, twice);
    }

    @Test
    void combineKeepsTheDataLength() {
        byte[] data = new byte[7];
        assertEquals(data.length, XorCombiner.combine(data, constantKeystream((byte) 1)).length);
    }
}
