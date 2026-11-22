package uaic.security.util;

import java.util.HexFormat;

import lombok.experimental.UtilityClass;

/**
 * Byte-array helpers shared by the byte-oriented ciphers: hex conversion,
 * word packing, XOR and constant-time comparison.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
public class Bytes {
    private static final int BYTE_MASK = 0xFF;
    private static final String WHITESPACE_PATTERN = "\\s";
    private static final HexFormat HEX_FORMAT = HexFormat.of();

    /**
     * Parses a hexadecimal string, ignoring any whitespace so that test
     * vectors can be pasted as printed in the standards.
     *
     * @param hex pairs of hex digits, optionally separated by whitespace
     * @return the decoded bytes
     * @throws IllegalArgumentException if the string is not valid hex
     */
    public static byte[] fromHex(String hex) {
        String compactHex = hex.replaceAll(WHITESPACE_PATTERN, "");
        return HEX_FORMAT.parseHex(compactHex);
    }

    /**
     * Formats bytes as lower-case hexadecimal without separators.
     *
     * @param bytes the bytes to format
     * @return two hex digits per byte
     */
    public static String toHex(byte[] bytes) {
        return HEX_FORMAT.formatHex(bytes);
    }

    /**
     * XORs two arrays of equal length byte by byte.
     *
     * @param left  the first operand
     * @param right the second operand
     * @return a new array holding {@code left XOR right}
     * @throws IllegalArgumentException if the lengths differ
     */
    public static byte[] xor(byte[] left, byte[] right) {
        if (left.length != right.length) {
            throw new IllegalArgumentException(
                    "Cannot XOR arrays of different lengths: " + left.length + " and " + right.length);
        }
        byte[] result = new byte[left.length];
        for (int index = 0; index < left.length; index++) {
            result[index] = (byte) (left[index] ^ right[index]);
        }
        return result;
    }

    /**
     * Compares two arrays without stopping at the first difference, so the
     * running time does not reveal where they differ.
     *
     * @param left  the first array
     * @param right the second array
     * @return {@code true} if both arrays hold the same bytes
     */
    public static boolean constantTimeEquals(byte[] left, byte[] right) {
        if (left.length != right.length) {
            return false;
        }
        int difference = 0;
        for (int index = 0; index < left.length; index++) {
            difference |= left[index] ^ right[index];
        }
        return difference == 0;
    }

    /**
     * Reads four bytes as a 32-bit word, least significant byte first.
     *
     * @param source the array to read from
     * @param offset the index of the least significant byte
     * @return the packed word
     */
    public static int readIntLittleEndian(byte[] source, int offset) {
        int word = 0;
        for (int byteIndex = Integer.BYTES - 1; byteIndex >= 0; byteIndex--) {
            int unsignedByte = source[offset + byteIndex] & BYTE_MASK;
            word = (word << Byte.SIZE) | unsignedByte;
        }
        return word;
    }

    /**
     * Writes a 32-bit word as four bytes, least significant byte first.
     *
     * @param word   the word to unpack
     * @param target the array to write into
     * @param offset the index receiving the least significant byte
     */
    public static void writeIntLittleEndian(int word, byte[] target, int offset) {
        for (int byteIndex = 0; byteIndex < Integer.BYTES; byteIndex++) {
            target[offset + byteIndex] = (byte) (word >>> (byteIndex * Byte.SIZE));
        }
    }
}
