package uaic.security.mode;

import java.util.ArrayList;
import java.util.List;

import lombok.NonNull;
import uaic.security.block.BlockCipher;

/**
 * Counter mode (NIST SP 800-38A, section 6.5): encrypts successive counter
 * blocks {@code T_1, T_2, ...} and XORs the outputs with the message,
 * {@code C_j = P_j XOR CIPH_K(T_j)}. A final partial block uses only the
 * leading bytes of its output block, so no padding is needed.
 *
 * <p>
 * Successive counters come from the standard incrementing function of
 * appendix B.1 applied to the whole block: {@code T_(j+1) = T_j + 1 mod 2^b}.
 * Encryption and decryption are the same operation.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public class CtrMode implements BlockMode {
    private static final int BYTE_MASK = 0xFF;

    private final BlockCipher blockCipher;
    private final byte[] initialCounterBlock;

    /**
     * @param blockCipher         the block transform
     * @param initialCounterBlock {@code T_1}, one block; counter blocks must
     *                            never repeat under the same key
     * @throws IllegalArgumentException if the counter is not one block long
     */
    public CtrMode(@NonNull BlockCipher blockCipher, @NonNull byte[] initialCounterBlock) {
        Blocks.requireOneBlock(initialCounterBlock, blockCipher.blockSize(), "CTR initial counter block");
        this.blockCipher = blockCipher;
        this.initialCounterBlock = initialCounterBlock.clone();
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return xorWithCounterKeystream(plaintext);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        return xorWithCounterKeystream(ciphertext);
    }

    private byte[] xorWithCounterKeystream(byte[] data) {
        List<byte[]> outputSegments = new ArrayList<>();
        byte[] counterBlock = initialCounterBlock;
        for (byte[] segment : Blocks.split(data, blockCipher.blockSize())) {
            byte[] keystreamBlock = blockCipher.encryptBlock(counterBlock);
            outputSegments.add(Blocks.xorWithLeadingBytes(segment, keystreamBlock));
            counterBlock = increment(counterBlock);
        }
        return Blocks.join(outputSegments);
    }

    /**
     * Adds one to the block read as a big-endian unsigned integer, wrapping
     * to zero after the maximum value.
     */
    static byte[] increment(byte[] counterBlock) {
        byte[] next = counterBlock.clone();
        int index = next.length - 1;
        boolean carry = true;
        while (carry && index >= 0) {
            next[index]++;
            carry = (next[index] & BYTE_MASK) == 0;
            index--;
        }
        return next;
    }
}
