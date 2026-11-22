package uaic.security.block.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import uaic.security.util.Bytes;

/** Round-by-round states of the FIPS 197 (2023 update) Appendix B cipher example. */
class AesRoundOpsTest {

    @ParameterizedTest(name = "round {0}")
    @CsvFileSource(resources = "/fips197/cipher-example-b.csv")
    void shiftRowsMatchesAppendixB(int round, String startHex, String afterSubBytesHex, String afterShiftRowsHex,
            String afterMixColumnsHex, String roundKeyHex) {
        if (afterShiftRowsHex == null) {
            return;
        }
        byte[] afterSubBytes = Bytes.fromHex(afterSubBytesHex);
        byte[] afterShiftRows = Bytes.fromHex(afterShiftRowsHex);
        assertArrayEquals(afterShiftRows, AesRoundOps.shiftRows(afterSubBytes));
        assertArrayEquals(afterSubBytes, AesRoundOps.inverseShiftRows(afterShiftRows));
    }

    @ParameterizedTest(name = "round {0}")
    @CsvFileSource(resources = "/fips197/cipher-example-b.csv")
    void mixColumnsMatchesAppendixB(int round, String startHex, String afterSubBytesHex, String afterShiftRowsHex,
            String afterMixColumnsHex, String roundKeyHex) {
        if (afterMixColumnsHex == null) {
            return;
        }
        byte[] afterShiftRows = Bytes.fromHex(afterShiftRowsHex);
        byte[] afterMixColumns = Bytes.fromHex(afterMixColumnsHex);
        assertArrayEquals(afterMixColumns, AesRoundOps.mixColumns(afterShiftRows));
        assertArrayEquals(afterShiftRows, AesRoundOps.inverseMixColumns(afterMixColumns));
    }

    /** Row r moves r places left; with bytes 00..0f, s[r,c] starts as r + 4c. */
    @Test
    void shiftRowsRotatesEachRowByItsIndex() {
        byte[] state = Bytes.fromHex("000102030405060708090a0b0c0d0e0f");
        byte[] expected = Bytes.fromHex("00050a0f04090e03080d02070c01060b");
        assertArrayEquals(expected, AesRoundOps.shiftRows(state));
    }

    @Test
    void mixColumnsOfZeroIsZero() {
        assertArrayEquals(new byte[16], AesRoundOps.mixColumns(new byte[16]));
    }
}
