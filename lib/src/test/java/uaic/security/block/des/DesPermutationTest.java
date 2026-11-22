package uaic.security.block.des;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class DesPermutationTest {

    @Test
    void identityTableKeepsTheBits() {
        assertEquals(0b1011L, DesPermutation.apply(0b1011L, 4, new int[] { 1, 2, 3, 4 }));
    }

    @Test
    void positionOneIsTheMostSignificantBit() {
        assertEquals(0b1L, DesPermutation.apply(0b1000L, 4, new int[] { 1 }));
    }

    @Test
    void reversingTableReversesTheBits() {
        assertEquals(0b0011L, DesPermutation.apply(0b1100L, 4, new int[] { 4, 3, 2, 1 }));
    }

    @Test
    void tableMayRepeatAndDropBits() {
        assertEquals(0b1110L, DesPermutation.apply(0b100L, 3, new int[] { 1, 1, 1, 3 }));
    }

    @Test
    void initialAndFinalPermutationsCancelOut() {
        long block = 0x0123456789abcdefL;
        long permuted = DesPermutation.apply(block, 64, DesTables.INITIAL_PERMUTATION);
        assertEquals(block, DesPermutation.apply(permuted, 64, DesTables.FINAL_PERMUTATION));
    }
}
