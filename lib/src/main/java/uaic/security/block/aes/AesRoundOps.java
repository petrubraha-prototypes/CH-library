package uaic.security.block.aes;

import lombok.experimental.UtilityClass;

/**
 * The AES state permutations SHIFTROWS() and MIXCOLUMNS() and their inverses
 * (FIPS 197, sections 5.1.2, 5.1.3, 5.3.1 and 5.3.3).
 *
 * <p>
 * The state is the 16-byte block in input order, so byte {@code s[r,c]}
 * (row r, column c) sits at index {@code r + 4c} (section 3.4).
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
class AesRoundOps {
    private static final int ROWS = 4;
    private static final int COLUMNS = 4;
    private static final int BYTE_MASK = 0xFF;

    /** Eq. 5.7: the MIXCOLUMNS() matrix built from the word [{02}, {01}, {01}, {03}]. */
    private static final int[][] MIX_MATRIX = {
            { 0x02, 0x03, 0x01, 0x01 },
            { 0x01, 0x02, 0x03, 0x01 },
            { 0x01, 0x01, 0x02, 0x03 },
            { 0x03, 0x01, 0x01, 0x02 } };

    /** Eq. 5.14: the INVMIXCOLUMNS() matrix built from the word [{0e}, {09}, {0d}, {0b}]. */
    private static final int[][] INVERSE_MIX_MATRIX = {
            { 0x0e, 0x0b, 0x0d, 0x09 },
            { 0x09, 0x0e, 0x0b, 0x0d },
            { 0x0d, 0x09, 0x0e, 0x0b },
            { 0x0b, 0x0d, 0x09, 0x0e } };

    /** Eq. 5.5: {@code s'[r,c] = s[r,(c + r) mod 4]}, rotating row r left by r. */
    static byte[] shiftRows(byte[] state) {
        byte[] shifted = new byte[state.length];
        for (int row = 0; row < ROWS; row++) {
            for (int column = 0; column < COLUMNS; column++) {
                int sourceColumn = (column + row) % COLUMNS;
                shifted[index(row, column)] = state[index(row, sourceColumn)];
            }
        }
        return shifted;
    }

    /** Eq. 5.12: {@code s'[r,c] = s[r,(c - r) mod 4]}, rotating row r right by r. */
    static byte[] inverseShiftRows(byte[] state) {
        byte[] shifted = new byte[state.length];
        for (int row = 0; row < ROWS; row++) {
            for (int column = 0; column < COLUMNS; column++) {
                int sourceColumn = (column - row + COLUMNS) % COLUMNS;
                shifted[index(row, column)] = state[index(row, sourceColumn)];
            }
        }
        return shifted;
    }

    /** Eq. 5.8: multiplies every column by the MIXCOLUMNS() matrix in GF(2^8). */
    static byte[] mixColumns(byte[] state) {
        return multiplyColumns(state, MIX_MATRIX);
    }

    /** Eq. 5.15: multiplies every column by the INVMIXCOLUMNS() matrix in GF(2^8). */
    static byte[] inverseMixColumns(byte[] state) {
        return multiplyColumns(state, INVERSE_MIX_MATRIX);
    }

    private static byte[] multiplyColumns(byte[] state, int[][] matrix) {
        byte[] mixed = new byte[state.length];
        for (int column = 0; column < COLUMNS; column++) {
            for (int row = 0; row < ROWS; row++) {
                int sum = 0;
                for (int term = 0; term < ROWS; term++) {
                    int stateByte = state[index(term, column)] & BYTE_MASK;
                    sum ^= AesGaloisField.multiply(matrix[row][term], stateByte);
                }
                mixed[index(row, column)] = (byte) sum;
            }
        }
        return mixed;
    }

    private static int index(int row, int column) {
        return row + ROWS * column;
    }
}
