package uaic.security.block.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.CsvSource;

import uaic.security.util.Bytes;

/** Intermediate values of FIPS 197 (2023 update), Appendix A.1, Table 5 and Appendix B. */
class AesKeyScheduleTest {

    private static final byte[] APPENDIX_KEY = Bytes.fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    private static final int WORDS_PER_ROUND_KEY = 4;

    private static int word(String hex) {
        return Integer.parseUnsignedInt(hex, 16);
    }

    private static int expandedWord(AesKeySchedule schedule, int index) {
        byte[] roundKey = schedule.roundKey(index / WORDS_PER_ROUND_KEY);
        int offset = (index % WORDS_PER_ROUND_KEY) * Integer.BYTES;
        byte[] wordBytes = Arrays.copyOfRange(roundKey, offset, offset + Integer.BYTES);
        return Bytes.toIntsBigEndian(wordBytes)[0];
    }

    @ParameterizedTest(name = "w[{0}]")
    @CsvFileSource(resources = "/fips197/key-expansion-a1.csv")
    void expandedWordsMatchAppendixA1(int index, String tempHex, String afterRotWordHex, String afterSubWordHex,
            String roundConstantHex, String afterXorHex, String earlierWordHex, String wordHex) {
        AesKeySchedule schedule = new AesKeySchedule(APPENDIX_KEY);
        assertEquals(word(tempHex), expandedWord(schedule, index - 1));
        assertEquals(word(earlierWordHex), expandedWord(schedule, index - WORDS_PER_ROUND_KEY));
        assertEquals(word(wordHex), expandedWord(schedule, index));
    }

    @ParameterizedTest(name = "i = {0}")
    @CsvFileSource(resources = "/fips197/key-expansion-a1.csv")
    void wordTransformationsMatchAppendixA1(int index, String tempHex, String afterRotWordHex,
            String afterSubWordHex, String roundConstantHex, String afterXorHex, String earlierWordHex,
            String wordHex) {
        if (afterRotWordHex == null) {
            return;
        }
        int afterRotWord = AesKeySchedule.rotWord(word(tempHex));
        int afterSubWord = AesKeySchedule.subWord(afterRotWord);
        int roundConstant = AesKeySchedule.roundConstant(index / WORDS_PER_ROUND_KEY);
        assertEquals(word(afterRotWordHex), afterRotWord);
        assertEquals(word(afterSubWordHex), afterSubWord);
        assertEquals(word(roundConstantHex), roundConstant);
        assertEquals(word(afterXorHex), afterSubWord ^ roundConstant);
    }

    /** Table 5. */
    @ParameterizedTest
    @CsvSource({ "1, 01", "2, 02", "3, 04", "4, 08", "5, 10", "6, 20", "7, 40", "8, 80", "9, 1b", "10, 36" })
    void roundConstantsMatchTable5(int roundNumber, String firstByteHex) {
        assertEquals(Integer.parseInt(firstByteHex, 16) << 24, AesKeySchedule.roundConstant(roundNumber));
    }

    @ParameterizedTest(name = "round {0}")
    @CsvFileSource(resources = "/fips197/cipher-example-b.csv")
    void roundKeysMatchAppendixB(int round, String startHex, String afterSubBytesHex, String afterShiftRowsHex,
            String afterMixColumnsHex, String roundKeyHex) {
        if (roundKeyHex == null) {
            return;
        }
        AesKeySchedule schedule = new AesKeySchedule(APPENDIX_KEY);
        assertArrayEquals(Bytes.fromHex(roundKeyHex), schedule.roundKey(round));
    }

    @Test
    void firstRoundKeyIsTheKey() {
        assertArrayEquals(APPENDIX_KEY, new AesKeySchedule(APPENDIX_KEY).roundKey(0));
    }

    @Test
    void rejectsKeyOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> new AesKeySchedule(new byte[24]));
    }
}
