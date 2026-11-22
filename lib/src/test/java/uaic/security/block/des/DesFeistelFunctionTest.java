package uaic.security.block.des;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class DesFeistelFunctionTest {

    private static final long HALF_BLOCK_LIMIT = 1L << 32;
    private final DesFeistelFunction feistelFunction = new DesFeistelFunction();

    /** All-zero groups read row 0, column 0 of every box: 14, 15, 10, 7, 2, 12, 4, 13. */
    @Test
    void substituteOfZeroReadsTheFirstEntryOfEachBox() {
        assertEquals(0xEFA72C4DL, DesFeistelFunction.substitute(0L));
    }

    /** FIPS 46-3 worked example: S1(011011) = 0101; the other groups stay zero. */
    @Test
    void substituteMatchesTheWorkedExample() {
        long firstGroup = 0b011011L << 42;
        assertEquals(0x5FA72C4DL, DesFeistelFunction.substitute(firstGroup));
    }

    /** The last group is S8: 000001 reads row 1, column 0 of S8, which is 1. */
    @Test
    void substituteReadsTheRowFromTheOuterBits() {
        assertEquals(0xEFA72C41L, DesFeistelFunction.substitute(0b000001L));
    }

    /** f depends on R and K only through E(R) XOR K. */
    @Test
    void outputDependsOnlyOnExpandedHalfXorSubkey() {
        long rightHalf = 0xF0AAF0AAL;
        long expanded = DesPermutation.apply(rightHalf, 32, DesTables.EXPANSION);
        assertEquals(feistelFunction.apply(0L, 0L), feistelFunction.apply(rightHalf, expanded));
    }

    @Test
    void outputIsThePermutedSubstitution() {
        long expected = DesPermutation.apply(0xEFA72C4DL, 32, DesTables.PERMUTATION);
        assertEquals(expected, feistelFunction.apply(0L, 0L));
    }

    @Test
    void subkeyChangesTheOutput() {
        long rightHalf = 0x12345678L;
        assertNotEquals(feistelFunction.apply(rightHalf, 0L), feistelFunction.apply(rightHalf, 1L));
    }

    @Test
    void outputIsThirtyTwoBits() {
        long output = feistelFunction.apply(0xFFFFFFFFL, 0xFFFFFFFFFFFFL);
        assertTrue(output >= 0 && output < HALF_BLOCK_LIMIT);
    }
}
