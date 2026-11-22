package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import uaic.security.util.Bytes;

/** Expected paddings follow the rule of RFC 5652, section 6.3. */
class Pkcs7PaddingTest {

    private static final int BLOCK_SIZE = 8;
    private final Padding padding = new Pkcs7Padding();

    @ParameterizedTest
    @CsvSource({
            "'', 0808080808080808",
            "aa, aa07070707070707",
            "aabbccddeeff00, aabbccddeeff0001",
            "aabbccddeeff0011, aabbccddeeff00110808080808080808",
            "aabbccddeeff001122, aabbccddeeff00112207070707070707",
    })
    void padAppendsTheMissingByteCount(String dataHex, String expectedHex) {
        byte[] data = Bytes.fromHex(dataHex);
        assertArrayEquals(Bytes.fromHex(expectedHex), padding.pad(data, BLOCK_SIZE));
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 7, 8, 9, 16, 31 })
    void roundTrip(int dataLength) {
        byte[] data = new byte[dataLength];
        for (int index = 0; index < dataLength; index++) {
            data[index] = (byte) (index + 1);
        }
        assertArrayEquals(data, padding.unpad(padding.pad(data, BLOCK_SIZE), BLOCK_SIZE));
    }

    @Test
    void padDoesNotModifyTheInput() {
        byte[] data = Bytes.fromHex("0102");
        padding.pad(data, BLOCK_SIZE);
        assertArrayEquals(Bytes.fromHex("0102"), data);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "aabbccddeeff0000",
            "aabbccddeeff0009",
            "aabbccddeeff0203",
            "aabbccddeeff0303",
    })
    void unpadRejectsMalformedPadding(String paddedHex) {
        byte[] padded = Bytes.fromHex(paddedHex);
        assertThrows(IllegalArgumentException.class, () -> padding.unpad(padded, BLOCK_SIZE));
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "01", "0101010101010101 01" })
    void unpadRejectsPartialBlocks(String paddedHex) {
        byte[] padded = Bytes.fromHex(paddedHex);
        assertThrows(IllegalArgumentException.class, () -> padding.unpad(padded, BLOCK_SIZE));
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 256 })
    void rejectsBlockSizesOutsideTheScheme(int blockSize) {
        assertThrows(IllegalArgumentException.class, () -> padding.pad(new byte[1], blockSize));
    }
}
