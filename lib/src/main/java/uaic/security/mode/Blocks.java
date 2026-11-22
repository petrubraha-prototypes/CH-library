package uaic.security.mode;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import lombok.experimental.UtilityClass;
import uaic.security.util.Bytes;

/**
 * Splits messages into blocks and joins them back, the bookkeeping shared by
 * every mode of operation.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
class Blocks {
    /**
     * Checks that an IV or counter block is exactly one block long.
     *
     * @throws IllegalArgumentException if the length differs from the block size
     */
    static void requireOneBlock(byte[] value, int blockSize, String valueName) {
        if (value.length != blockSize) {
            throw new IllegalArgumentException(
                    valueName + " must be " + blockSize + " bytes, got " + value.length);
        }
    }

    /**
     * Splits data into whole blocks.
     *
     * @throws IllegalArgumentException if the length is not a multiple of the block size
     */
    static List<byte[]> splitWhole(byte[] data, int blockSize) {
        if (data.length % blockSize != 0) {
            throw new IllegalArgumentException("Data length " + data.length
                    + " is not a multiple of the block size " + blockSize);
        }
        return split(data, blockSize);
    }

    /** Splits data into blocks; only the last one may be shorter than the block size. */
    static List<byte[]> split(byte[] data, int blockSize) {
        List<byte[]> blocks = new ArrayList<>();
        for (int start = 0; start < data.length; start += blockSize) {
            int end = Math.min(start + blockSize, data.length);
            blocks.add(Arrays.copyOfRange(data, start, end));
        }
        return blocks;
    }

    /** Concatenates blocks in order. */
    static byte[] join(List<byte[]> blocks) {
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        blocks.forEach(joined::writeBytes);
        return joined.toByteArray();
    }

    /**
     * XORs a segment with the leading bytes of a cipher output block; the
     * rest of the output block is discarded, as for a final partial block.
     */
    static byte[] xorWithLeadingBytes(byte[] segment, byte[] outputBlock) {
        byte[] leadingBytes = Arrays.copyOf(outputBlock, segment.length);
        return Bytes.xor(segment, leadingBytes);
    }
}
