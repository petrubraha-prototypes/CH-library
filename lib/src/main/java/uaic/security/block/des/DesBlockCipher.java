package uaic.security.block.des;

import java.util.stream.IntStream;

import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

/**
 * The Data Encryption Standard (FIPS 46-3) on one 64-bit block. It only
 * sequences the steps: the initial permutation IP, sixteen Feistel rounds
 * {@code L_n = R_(n-1)}, {@code R_n = L_(n-1) XOR f(R_(n-1), K_n)}, the swap
 * to R16L16 and the final permutation IP-1.
 *
 * <p>
 * Decryption runs the same network with the subkeys in reverse order.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> A 56-bit key
 * can be found by exhaustive search.
 */
public class DesBlockCipher implements BlockCipher {
    private static final int BLOCK_SIZE = Long.BYTES;
    private static final int BLOCK_BITS = Long.SIZE;
    private static final int HALF_BITS = Integer.SIZE;
    private static final long HALF_MASK = 0xFFFFFFFFL;

    private static final int[] ENCRYPTION_SUBKEY_ORDER =
            IntStream.rangeClosed(1, DesKeySchedule.ROUNDS).toArray();
    private static final int[] DECRYPTION_SUBKEY_ORDER =
            IntStream.rangeClosed(1, DesKeySchedule.ROUNDS).map(round -> DesKeySchedule.ROUNDS + 1 - round).toArray();

    private final DesKeySchedule keySchedule;
    private final DesFeistelFunction feistelFunction = new DesFeistelFunction();

    /**
     * @param key 8 bytes; the lowest bit of each byte is a parity bit and is ignored
     * @throws IllegalArgumentException if the key is not 8 bytes
     */
    public DesBlockCipher(byte[] key) {
        this.keySchedule = new DesKeySchedule(key);
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public byte[] encryptBlock(byte[] plaintextBlock) {
        return runFeistelNetwork(plaintextBlock, ENCRYPTION_SUBKEY_ORDER);
    }

    @Override
    public byte[] decryptBlock(byte[] ciphertextBlock) {
        return runFeistelNetwork(ciphertextBlock, DECRYPTION_SUBKEY_ORDER);
    }

    private byte[] runFeistelNetwork(byte[] block, int[] subkeyOrder) {
        long inputBits = Bytes.toLongBigEndian(block);
        long permuted = DesPermutation.apply(inputBits, BLOCK_BITS, DesTables.INITIAL_PERMUTATION);
        long left = permuted >>> HALF_BITS;
        long right = permuted & HALF_MASK;
        for (int roundNumber : subkeyOrder) {
            long subkey = keySchedule.subkey(roundNumber);
            long nextRight = left ^ feistelFunction.apply(right, subkey);
            left = right;
            right = nextRight;
        }
        long preoutput = (right << HALF_BITS) | left;
        long outputBits = DesPermutation.apply(preoutput, BLOCK_BITS, DesTables.FINAL_PERMUTATION);
        return Bytes.fromLongBigEndian(outputBits);
    }
}
