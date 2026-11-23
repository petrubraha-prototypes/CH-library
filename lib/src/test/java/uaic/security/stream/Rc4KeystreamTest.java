package uaic.security.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import uaic.security.util.Bytes;

class Rc4KeystreamTest {

    private static final int VECTOR_LENGTH = 16;

    private static byte[] keystreamAt(byte[] key, int offset) {
        Keystream keystream = new Rc4Keystream(key);
        keystream.fill(new byte[offset]);
        byte[] output = new byte[VECTOR_LENGTH];
        keystream.fill(output);
        return output;
    }

    /** Known-answer vectors from RFC 6229, section 2. */
    @ParameterizedTest(name = "key {0} at offset {1}")
    @CsvSource({
            "0102030405, 0, b2396305f03dc027ccc3524a0a1118a8",
            "0102030405, 16, 6982944f18fc82d589c403a47a0d0919",
            "0102030405, 4096, ff25b58995996707e51fbdf08b34d875",
            "0102030405060708090a0b0c0d0e0f10, 0, 9ac7cc9a609d1ef7b2932899cde41b97",
            "0102030405060708090a0b0c0d0e0f10, 4096, a36a4c301ae8ac13610ccbc12256cacc",
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20, 0, eaa6bd25880bf93d3f5d1e4ca2611d91",
            "833222772a, 0, 80ad97bdc973df8a2e879e92a497efda",
            "1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a, 16, c8446f8f77abf737685353eb89a1c9eb",
    })
    void matchesRfc6229(String keyHex, int offset, String expectedHex) {
        byte[] key = Bytes.fromHex(keyHex);
        assertArrayEquals(Bytes.fromHex(expectedHex), keystreamAt(key, offset));
    }

    @Test
    void sameKeyGivesSameKeystream() {
        byte[] key = Bytes.fromHex("0102030405");
        assertArrayEquals(keystreamAt(key, 0), keystreamAt(key, 0));
    }

    @Test
    void differentKeysGiveDifferentKeystreams() {
        byte[] first = keystreamAt(Bytes.fromHex("0102030405"), 0);
        byte[] second = keystreamAt(Bytes.fromHex("0102030406"), 0);
        assertFalse(Arrays.equals(first, second));
    }

    @Test
    void acceptsKeyLengthBounds() {
        assertDoesNotThrow(() -> new Rc4Keystream(new byte[1]));
        assertDoesNotThrow(() -> new Rc4Keystream(new byte[256]));
    }

    @Test
    void rejectsEmptyKey() {
        assertThrows(IllegalArgumentException.class, () -> new Rc4Keystream(new byte[0]));
    }

    @Test
    void rejectsKeyLongerThanTheState() {
        assertThrows(IllegalArgumentException.class, () -> new Rc4Keystream(new byte[257]));
    }
}
