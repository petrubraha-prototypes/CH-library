package uaic.security.block.des;

/**
 * The DES cipher function f(R, K) of FIPS 46-3: expands the 32-bit half block
 * R to 48 bits with E, XORs it with the 48-bit subkey K, passes each 6-bit
 * group through its selection function S1 to S8 and permutes the resulting
 * 32 bits with P.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
class DesFeistelFunction {
    private static final int HALF_BLOCK_BITS = 32;
    private static final int EXPANDED_BITS = 48;
    private static final int SELECTION_INPUT_BITS = 6;
    private static final int SELECTION_OUTPUT_BITS = 4;
    private static final int SELECTION_INPUT_MASK = 0b111111;
    private static final int LOWEST_BIT = 0b1;
    private static final int MIDDLE_BITS_MASK = 0b1111;

    /**
     * Computes f(R, K).
     *
     * @param rightHalf the 32-bit half block R, right-aligned
     * @param subkey    the 48-bit subkey K, right-aligned
     * @return the 32-bit output, right-aligned
     */
    long apply(long rightHalf, long subkey) {
        long expanded = DesPermutation.apply(rightHalf, HALF_BLOCK_BITS, DesTables.EXPANSION);
        long mixed = expanded ^ subkey;
        long substituted = substitute(mixed);
        return DesPermutation.apply(substituted, HALF_BLOCK_BITS, DesTables.PERMUTATION);
    }

    /** Replaces each of the eight 6-bit groups B1 to B8 with the 4-bit Si(Bi). */
    static long substitute(long fortyEightBits) {
        long output = 0;
        for (int box = 0; box < DesTables.SELECTION_FUNCTIONS.length; box++) {
            int shift = EXPANDED_BITS - SELECTION_INPUT_BITS * (box + 1);
            int group = (int) (fortyEightBits >>> shift) & SELECTION_INPUT_MASK;
            int substitutedGroup = select(box, group);
            output = (output << SELECTION_OUTPUT_BITS) | substitutedGroup;
        }
        return output;
    }

    /** The first and last bits pick the row, the four middle bits pick the column. */
    private static int select(int box, int group) {
        int firstBit = (group >>> (SELECTION_INPUT_BITS - 1)) & LOWEST_BIT;
        int lastBit = group & LOWEST_BIT;
        int row = (firstBit << 1) | lastBit;
        int column = (group >>> 1) & MIDDLE_BITS_MASK;
        return DesTables.SELECTION_FUNCTIONS[box][row][column];
    }
}
