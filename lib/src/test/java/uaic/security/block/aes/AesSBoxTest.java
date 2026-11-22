package uaic.security.block.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import uaic.security.util.Bytes;

/** The computed tables against Tables 4 and 6 and Appendix B of FIPS 197 (2023 update). */
class AesSBoxTest {

    private static final int ROW_LENGTH = 16;

    @ParameterizedTest(name = "row {0}")
    @CsvFileSource(resources = "/fips197/sbox.csv")
    void substituteMatchesTable4(String rowHex, String valuesHex) {
        byte[] expected = Bytes.fromHex(valuesHex);
        int row = Integer.parseInt(rowHex, 16);
        for (int column = 0; column < ROW_LENGTH; column++) {
            int input = row * ROW_LENGTH + column;
            assertEquals(expected[column] & 0xFF, AesSBox.substitute(input), "SBOX(" + input + ")");
        }
    }

    @ParameterizedTest(name = "row {0}")
    @CsvFileSource(resources = "/fips197/inverse-sbox.csv")
    void inverseSubstituteMatchesTable6(String rowHex, String valuesHex) {
        byte[] expected = Bytes.fromHex(valuesHex);
        int row = Integer.parseInt(rowHex, 16);
        for (int column = 0; column < ROW_LENGTH; column++) {
            int input = row * ROW_LENGTH + column;
            assertEquals(expected[column] & 0xFF, AesSBox.inverseSubstitute(input), "INVSBOX(" + input + ")");
        }
    }

    /** Section 5.1.1 example: SBOX({53}) = {ed}. */
    @Test
    void substituteMatchesTheWorkedExample() {
        assertEquals(0xed, AesSBox.substitute(0x53));
    }

    @ParameterizedTest(name = "round {0}")
    @CsvFileSource(resources = "/fips197/cipher-example-b.csv")
    void subBytesMatchesAppendixB(int round, String startHex, String afterSubBytesHex, String afterShiftRowsHex,
            String afterMixColumnsHex, String roundKeyHex) {
        if (afterSubBytesHex == null) {
            return;
        }
        byte[] start = Bytes.fromHex(startHex);
        byte[] afterSubBytes = Bytes.fromHex(afterSubBytesHex);
        assertArrayEquals(afterSubBytes, AesSBox.subBytes(start));
        assertArrayEquals(start, AesSBox.inverseSubBytes(afterSubBytes));
    }
}
