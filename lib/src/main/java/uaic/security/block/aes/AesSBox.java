package uaic.security.block.aes;

import lombok.experimental.UtilityClass;

/**
 * The AES S-box and SUBBYTES() (FIPS 197, sections 5.1.1 and 5.3.2). The
 * table is built from its definition rather than copied: each byte is
 * replaced by its inverse in GF(2^8), then passed through the affine
 * transformation of Eq. 5.3. INVSBOX() is the same table read backwards.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
class AesSBox {
    private static final int FIELD_SIZE = 256;
    private static final int BYTE_MASK = 0xFF;
    private static final int BITS_PER_BYTE = Byte.SIZE;
    /** The constant c = {01100011} of Eq. 5.3. */
    private static final int AFFINE_CONSTANT = 0x63;
    /** Eq. 5.3 XORs bit i with bits i + 4, i + 5, i + 6 and i + 7 (mod 8). */
    private static final int[] AFFINE_BIT_OFFSETS = { 0, 4, 5, 6, 7 };

    private static final int[] SUBSTITUTION = buildSubstitution();
    private static final int[] INVERSE_SUBSTITUTION = invert(SUBSTITUTION);

    /**
     * SBOX(b).
     *
     * @param value a byte, 0 to 255
     * @return the substituted byte, 0 to 255
     */
    static int substitute(int value) {
        return SUBSTITUTION[value];
    }

    /**
     * INVSBOX(b).
     *
     * @param value a byte, 0 to 255
     * @return the byte that SBOX() maps to {@code value}
     */
    static int inverseSubstitute(int value) {
        return INVERSE_SUBSTITUTION[value];
    }

    /** SUBBYTES(): applies SBOX() to every byte of the state. */
    static byte[] subBytes(byte[] state) {
        return mapBytes(state, SUBSTITUTION);
    }

    /** INVSUBBYTES(): applies INVSBOX() to every byte of the state. */
    static byte[] inverseSubBytes(byte[] state) {
        return mapBytes(state, INVERSE_SUBSTITUTION);
    }

    private static byte[] mapBytes(byte[] state, int[] table) {
        byte[] result = new byte[state.length];
        for (int index = 0; index < state.length; index++) {
            result[index] = (byte) table[state[index] & BYTE_MASK];
        }
        return result;
    }

    private static int[] buildSubstitution() {
        int[] table = new int[FIELD_SIZE];
        for (int value = 0; value < FIELD_SIZE; value++) {
            int inverse = AesGaloisField.inverse(value);
            table[value] = affineTransform(inverse);
        }
        return table;
    }

    /** Eq. 5.3: b'_i = b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i, indices mod 8. */
    private static int affineTransform(int value) {
        int result = 0;
        for (int bitIndex = 0; bitIndex < BITS_PER_BYTE; bitIndex++) {
            int bit = bitAt(AFFINE_CONSTANT, bitIndex);
            for (int offset : AFFINE_BIT_OFFSETS) {
                bit ^= bitAt(value, (bitIndex + offset) % BITS_PER_BYTE);
            }
            result |= bit << bitIndex;
        }
        return result;
    }

    private static int bitAt(int value, int bitIndex) {
        return (value >>> bitIndex) & 1;
    }

    private static int[] invert(int[] table) {
        int[] inverse = new int[table.length];
        for (int value = 0; value < table.length; value++) {
            inverse[table[value]] = value;
        }
        return inverse;
    }
}
