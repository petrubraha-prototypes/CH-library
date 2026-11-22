package uaic.security.block.des;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

/** Checks the transcribed tables against the properties FIPS 46-3 states for them. */
class DesTablesTest {

    private static final int BLOCK_BITS = 64;
    private static final int HALF_BLOCK_BITS = 32;
    private static final int KEY_SCHEDULE_BITS = 56;
    private static final int HALF_KEY_BITS = 28;

    private static int[] oneTo(int last) {
        return IntStream.rangeClosed(1, last).toArray();
    }

    private static int[] sorted(int[] table) {
        int[] copy = table.clone();
        Arrays.sort(copy);
        return copy;
    }

    @Test
    void initialPermutationUsesEveryBitOnce() {
        assertArrayEquals(oneTo(BLOCK_BITS), sorted(DesTables.INITIAL_PERMUTATION));
    }

    @Test
    void finalPermutationIsTheInverseOfTheInitialPermutation() {
        for (int position = 1; position <= BLOCK_BITS; position++) {
            int afterFinal = DesTables.FINAL_PERMUTATION[position - 1];
            assertEquals(position, DesTables.INITIAL_PERMUTATION[afterFinal - 1]);
        }
    }

    /** FIPS 46-3: the first three bits of E(R) are bits 32, 1, 2 and the last two are 32, 1. */
    @Test
    void expansionWrapsAroundTheHalfBlock() {
        int[] expansion = DesTables.EXPANSION;
        assertEquals(48, expansion.length);
        assertArrayEquals(new int[] { 32, 1, 2 }, Arrays.copyOfRange(expansion, 0, 3));
        assertArrayEquals(new int[] { 32, 1 }, Arrays.copyOfRange(expansion, 46, 48));
    }

    @Test
    void permutationUsesEveryBitOfTheHalfBlockOnce() {
        assertArrayEquals(oneTo(HALF_BLOCK_BITS), sorted(DesTables.PERMUTATION));
    }

    /** FIPS 46-3: bits 8, 16, ..., 64 of the key are parity bits. */
    @Test
    void permutedChoiceOneSkipsExactlyTheParityBits() {
        int[] nonParityBits = IntStream.rangeClosed(1, BLOCK_BITS).filter(bit -> bit % 8 != 0).toArray();
        assertArrayEquals(nonParityBits, sorted(DesTables.PERMUTED_CHOICE_1));
    }

    @Test
    void permutedChoiceTwoSelectsFortyEightDistinctBits() {
        int[] permutedChoice = DesTables.PERMUTED_CHOICE_2;
        assertEquals(48, permutedChoice.length);
        assertEquals(48, Arrays.stream(permutedChoice).distinct().count());
        assertTrue(Arrays.stream(permutedChoice).allMatch(bit -> bit >= 1 && bit <= KEY_SCHEDULE_BITS));
    }

    @Test
    void leftShiftsRotateEachHalfKeyOnceAroundInTotal() {
        assertEquals(16, DesTables.LEFT_SHIFTS.length);
        assertEquals(HALF_KEY_BITS, Arrays.stream(DesTables.LEFT_SHIFTS).sum());
    }

    @Test
    void everySelectionFunctionRowIsAPermutationOfZeroToFifteen() {
        int[] zeroToFifteen = IntStream.range(0, 16).toArray();
        for (int[][] selectionFunction : DesTables.SELECTION_FUNCTIONS) {
            for (int[] row : selectionFunction) {
                assertArrayEquals(zeroToFifteen, sorted(row));
            }
        }
    }

    /** FIPS 46-3 worked example: S1(011011) reads row 1, column 13 and gives 5. */
    @Test
    void firstSelectionFunctionMatchesTheWorkedExample() {
        assertEquals(5, DesTables.SELECTION_FUNCTIONS[0][1][13]);
    }
}
