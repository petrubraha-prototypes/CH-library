package uaic.security.block.des;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.LongStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import uaic.security.util.Bytes;

/**
 * Weak, semi-weak and possibly weak keys are the ones listed in NIST SP
 * 800-67 Rev. 2, section 3.3.2; their subkey patterns are what makes them weak.
 */
class DesKeyScheduleTest {

    private static final long SUBKEY_LIMIT = 1L << 48;

    private static long[] subkeys(String keyHex) {
        DesKeySchedule schedule = new DesKeySchedule(Bytes.fromHex(keyHex));
        return LongStream.rangeClosed(1, DesKeySchedule.ROUNDS).map(round -> schedule.subkey((int) round)).toArray();
    }

    @ParameterizedTest
    @ValueSource(strings = { "0101010101010101", "FEFEFEFEFEFEFEFE", "E0E0E0E0F1F1F1F1", "1F1F1F1F0E0E0E0E" })
    void weakKeysRepeatOneSubkey(String keyHex) {
        assertEquals(1, LongStream.of(subkeys(keyHex)).distinct().count());
    }

    @ParameterizedTest
    @ValueSource(strings = { "01011F1F01010E0E", "1F1F01010E0E0101", "E0E01F1FF1F10E0E" })
    void possiblyWeakKeysProduceFourDistinctSubkeys(String keyHex) {
        assertEquals(4, LongStream.of(subkeys(keyHex)).distinct().count());
    }

    /** A semi-weak pair undoes each other because one schedule is the other reversed. */
    @ParameterizedTest
    @CsvSource({
            "011F011F010E010E, 1F011F010E010E01",
            "01E001E001F101F1, E001E001F101F101",
            "01FE01FE01FE01FE, FE01FE01FE01FE01",
    })
    void semiWeakPairsHaveReversedSchedules(String firstKeyHex, String secondKeyHex) {
        long[] first = subkeys(firstKeyHex);
        long[] second = subkeys(secondKeyHex);
        for (int round = 0; round < DesKeySchedule.ROUNDS; round++) {
            assertEquals(first[round], second[DesKeySchedule.ROUNDS - 1 - round]);
        }
    }

    @Test
    void parityBitsAreIgnored() {
        long[] withParity = subkeys("133457799BBCDFF1");
        long[] parityFlipped = subkeys("123456789ABCDEF0");
        assertEquals(LongStream.of(withParity).boxed().toList(), LongStream.of(parityFlipped).boxed().toList());
    }

    @Test
    void differentKeysGiveDifferentFirstSubkeys() {
        assertNotEquals(subkeys("133457799BBCDFF1")[0], subkeys("0E329232EA6D0D73")[0]);
    }

    @Test
    void subkeysAreFortyEightBits() {
        for (long subkey : subkeys("133457799BBCDFF1")) {
            assertTrue(subkey >= 0 && subkey < SUBKEY_LIMIT);
        }
    }

    @Test
    void rejectsKeyOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> new DesKeySchedule(new byte[7]));
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 17 })
    void rejectsRoundNumbersOutsideOneToSixteen(int roundNumber) {
        DesKeySchedule schedule = new DesKeySchedule(new byte[8]);
        assertThrows(IllegalArgumentException.class, () -> schedule.subkey(roundNumber));
    }
}
