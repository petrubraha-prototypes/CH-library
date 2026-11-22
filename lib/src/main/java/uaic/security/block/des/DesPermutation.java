package uaic.security.block.des;

import lombok.experimental.UtilityClass;

/**
 * Applies a DES bit-selection table: output bit {@code i} is the input bit
 * at position {@code table[i - 1]}, with positions numbered from 1 at the
 * most significant bit, as in FIPS 46-3. The same rule drives IP, IP-1, E,
 * P, PC-1 and PC-2.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
class DesPermutation {
    private static final long LOWEST_BIT = 1L;

    /**
     * @param input         the bits to select from, right-aligned in a long
     * @param inputBitCount how many low-order bits of {@code input} are used
     * @param table         1-based input positions, one per output bit
     * @return {@code table.length} bits, right-aligned
     */
    static long apply(long input, int inputBitCount, int[] table) {
        long output = 0;
        for (int position : table) {
            long selectedBit = (input >>> (inputBitCount - position)) & LOWEST_BIT;
            output = (output << 1) | selectedBit;
        }
        return output;
    }
}
