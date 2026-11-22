package uaic.security.mode;

import java.util.Arrays;

import uaic.security.util.Bytes;

/**
 * PKCS#7 padding (RFC 5652, section 6.3): appends {@code k - (length mod k)}
 * bytes, each holding that same value, where {@code k} is the block size.
 *
 * <p>
 * A message that already fills its last block still gets a whole block of
 * padding, so the padding can always be removed unambiguously. The scheme is
 * defined for block sizes below 256.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public class Pkcs7Padding implements Padding {
    private static final int MINIMUM_BLOCK_SIZE = 1;
    private static final int MAXIMUM_BLOCK_SIZE = 255;
    private static final int MINIMUM_PADDING_LENGTH = 1;
    private static final int BYTE_MASK = 0xFF;

    @Override
    public byte[] pad(byte[] data, int blockSize) {
        validateBlockSize(blockSize);
        int paddingLength = blockSize - data.length % blockSize;
        byte[] padded = Arrays.copyOf(data, data.length + paddingLength);
        Arrays.fill(padded, data.length, padded.length, (byte) paddingLength);
        return padded;
    }

    @Override
    public byte[] unpad(byte[] paddedData, int blockSize) {
        validateBlockSize(blockSize);
        if (paddedData.length == 0 || paddedData.length % blockSize != 0) {
            throw new IllegalArgumentException("Padded data length " + paddedData.length
                    + " is not a positive multiple of the block size " + blockSize);
        }
        int paddingLength = paddedData[paddedData.length - 1] & BYTE_MASK;
        if (!hasValidPadding(paddedData, paddingLength, blockSize)) {
            throw new IllegalArgumentException("Invalid PKCS#7 padding");
        }
        return Arrays.copyOf(paddedData, paddedData.length - paddingLength);
    }

    private static boolean hasValidPadding(byte[] paddedData, int paddingLength, int blockSize) {
        if (paddingLength < MINIMUM_PADDING_LENGTH || paddingLength > blockSize) {
            return false;
        }
        byte[] actualPadding = Arrays.copyOfRange(paddedData, paddedData.length - paddingLength,
                paddedData.length);
        byte[] expectedPadding = new byte[paddingLength];
        Arrays.fill(expectedPadding, (byte) paddingLength);
        return Bytes.constantTimeEquals(actualPadding, expectedPadding);
    }

    private static void validateBlockSize(int blockSize) {
        if (blockSize < MINIMUM_BLOCK_SIZE || blockSize > MAXIMUM_BLOCK_SIZE) {
            throw new IllegalArgumentException("PKCS#7 block size must be between " + MINIMUM_BLOCK_SIZE
                    + " and " + MAXIMUM_BLOCK_SIZE + ", got " + blockSize);
        }
    }
}
