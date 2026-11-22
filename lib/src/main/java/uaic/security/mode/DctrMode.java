package uaic.security.mode;

import lombok.NonNull;
import uaic.security.block.BlockCipher;

/**
 * Deterministic counter mode (dCTR): {@link CtrMode} whose first counter
 * block is a fixed number, 1 by default, written big-endian into one block.
 * There is no random nonce.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> Every message
 * under the same key reuses the same keystream, so XORing two ciphertexts
 * cancels it and reveals the XOR of the plaintexts.
 */
public class DctrMode implements BlockMode {
    private static final long DEFAULT_INITIAL_COUNTER = 1;
    private static final int BYTE_MASK = 0xFF;

    private final CtrMode counterMode;

    /**
     * Starts counting at 1.
     *
     * @param blockCipher the block transform
     */
    public DctrMode(BlockCipher blockCipher) {
        this(blockCipher, DEFAULT_INITIAL_COUNTER);
    }

    /**
     * @param blockCipher    the block transform
     * @param initialCounter the non-negative value of the first counter block
     * @throws IllegalArgumentException if the counter is negative or does not fit in one block
     */
    public DctrMode(@NonNull BlockCipher blockCipher, long initialCounter) {
        byte[] initialCounterBlock = counterBlock(initialCounter, blockCipher.blockSize());
        this.counterMode = new CtrMode(blockCipher, initialCounterBlock);
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return counterMode.encrypt(plaintext);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        return counterMode.decrypt(ciphertext);
    }

    /** Writes the counter big-endian into the low-order bytes of a zeroed block. */
    static byte[] counterBlock(long counter, int blockSize) {
        if (counter < 0) {
            throw new IllegalArgumentException("dCTR initial counter must not be negative, got " + counter);
        }
        byte[] block = new byte[blockSize];
        long remaining = counter;
        for (int index = blockSize - 1; index >= 0 && remaining != 0; index--) {
            block[index] = (byte) (remaining & BYTE_MASK);
            remaining >>>= Byte.SIZE;
        }
        if (remaining != 0) {
            throw new IllegalArgumentException(
                    "dCTR initial counter " + counter + " does not fit in " + blockSize + " bytes");
        }
        return block;
    }
}
