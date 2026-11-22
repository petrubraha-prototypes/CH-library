package uaic.security.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class BytesTest {

    @Test
    void fromHexDecodesPairsOfDigits() {
        byte[] expected = { 0x00, 0x7f, (byte) 0x80, (byte) 0xff };
        assertArrayEquals(expected, Bytes.fromHex("007f80FF"));
    }

    @Test
    void fromHexIgnoresWhitespace() {
        assertArrayEquals(Bytes.fromHex("00112233"), Bytes.fromHex("00 11\n22\t33"));
    }

    @Test
    void fromHexRejectsOddLength() {
        assertThrows(IllegalArgumentException.class, () -> Bytes.fromHex("abc"));
    }

    @Test
    void fromHexRejectsNonHexDigits() {
        assertThrows(IllegalArgumentException.class, () -> Bytes.fromHex("zz"));
    }

    @Test
    void toHexFormatsLowerCase() {
        byte[] bytes = { 0x0a, (byte) 0xbc, (byte) 0xff };
        assertEquals("0abcff", Bytes.toHex(bytes));
    }

    @Test
    void hexRoundTrip() {
        String hex = "000102030405060708090a0b0c0d0e0f";
        assertEquals(hex, Bytes.toHex(Bytes.fromHex(hex)));
    }

    @Test
    void xorCombinesByteByByte() {
        byte[] left = Bytes.fromHex("ff00aa");
        byte[] right = Bytes.fromHex("0f0f55");
        assertArrayEquals(Bytes.fromHex("f00fff"), Bytes.xor(left, right));
    }

    @Test
    void xorWithItselfIsZero() {
        byte[] data = Bytes.fromHex("deadbeef");
        assertArrayEquals(new byte[data.length], Bytes.xor(data, data));
    }

    @Test
    void xorDoesNotModifyOperands() {
        byte[] left = Bytes.fromHex("0102");
        byte[] right = Bytes.fromHex("0304");
        Bytes.xor(left, right);
        assertArrayEquals(Bytes.fromHex("0102"), left);
        assertArrayEquals(Bytes.fromHex("0304"), right);
    }

    @Test
    void xorRejectsDifferentLengths() {
        assertThrows(IllegalArgumentException.class, () -> Bytes.xor(new byte[2], new byte[3]));
    }

    @Test
    void constantTimeEqualsAcceptsEqualArrays() {
        assertTrue(Bytes.constantTimeEquals(Bytes.fromHex("a1b2"), Bytes.fromHex("a1b2")));
    }

    @Test
    void constantTimeEqualsRejectsDifferentContent() {
        assertFalse(Bytes.constantTimeEquals(Bytes.fromHex("a1b2"), Bytes.fromHex("a1b3")));
    }

    @Test
    void constantTimeEqualsRejectsDifferentLengths() {
        assertFalse(Bytes.constantTimeEquals(Bytes.fromHex("a1"), Bytes.fromHex("a1b2")));
    }

    @Test
    void readIntLittleEndianPutsFirstByteLowest() {
        byte[] source = Bytes.fromHex("ff 01020304");
        assertEquals(0x04030201, Bytes.readIntLittleEndian(source, 1));
    }

    @Test
    void readIntLittleEndianTreatsBytesAsUnsigned() {
        byte[] source = Bytes.fromHex("ffffffff");
        assertEquals(-1, Bytes.readIntLittleEndian(source, 0));
    }

    @Test
    void writeIntLittleEndianPutsLowestByteFirst() {
        byte[] target = new byte[5];
        Bytes.writeIntLittleEndian(0x04030201, target, 1);
        assertArrayEquals(Bytes.fromHex("00 01020304"), target);
    }

    @Test
    void littleEndianWordRoundTrip() {
        byte[] target = new byte[Integer.BYTES];
        Bytes.writeIntLittleEndian(0x89abcdef, target, 0);
        assertEquals(0x89abcdef, Bytes.readIntLittleEndian(target, 0));
    }

    /** Examples of the littleendian function from the Salsa20 specification, section 7. */
    @Test
    void toIntsLittleEndianMatchesTheSalsa20SpecificationExamples() {
        byte[] bytes = { 0, 0, 0, 0, 86, 75, 30, 9, (byte) 255, (byte) 255, (byte) 255, (byte) 250 };
        int[] expected = { 0x00000000, 0x091e4b56, 0xfaffffff };
        assertArrayEquals(expected, Bytes.toIntsLittleEndian(bytes));
    }

    @Test
    void toIntsLittleEndianRejectsPartialWords() {
        assertThrows(IllegalArgumentException.class, () -> Bytes.toIntsLittleEndian(new byte[5]));
    }

    @Test
    void fromIntsLittleEndianUnpacksEachWord() {
        int[] words = { 0x04030201, 0x08070605 };
        assertArrayEquals(Bytes.fromHex("0102030405060708"), Bytes.fromIntsLittleEndian(words));
    }

    @Test
    void wordArrayRoundTrip() {
        byte[] bytes = Bytes.fromHex("00112233445566778899aabbccddeeff");
        assertArrayEquals(bytes, Bytes.fromIntsLittleEndian(Bytes.toIntsLittleEndian(bytes)));
    }

    @Test
    void toLongBigEndianPutsFirstByteHighest() {
        assertEquals(0x0123456789abcdefL, Bytes.toLongBigEndian(Bytes.fromHex("0123456789abcdef")));
    }

    @Test
    void toLongBigEndianRejectsOtherLengths() {
        assertThrows(IllegalArgumentException.class, () -> Bytes.toLongBigEndian(new byte[7]));
    }

    @Test
    void fromLongBigEndianPutsHighestByteFirst() {
        assertArrayEquals(Bytes.fromHex("fedcba9876543210"), Bytes.fromLongBigEndian(0xfedcba9876543210L));
    }
}
