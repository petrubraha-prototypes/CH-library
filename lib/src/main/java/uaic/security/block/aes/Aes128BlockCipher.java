package uaic.security.block.aes;

import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

/**
 * AES-128 (FIPS 197) on one 16-byte block. It only sequences the round
 * transformations, following CIPHER() (Algorithm 1) and INVCIPHER()
 * (Algorithm 3): an initial ADDROUNDKEY, nine full rounds of SUBBYTES,
 * SHIFTROWS, MIXCOLUMNS and ADDROUNDKEY, and a final round without
 * MIXCOLUMNS.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> Table lookups
 * and GF arithmetic here are not constant-time.
 */
public class Aes128BlockCipher implements BlockCipher {
    private static final int BLOCK_SIZE = 16;
    private static final int ROUNDS = AesKeySchedule.ROUNDS;
    private static final int INITIAL_ROUND = 0;

    private final AesKeySchedule keySchedule;

    /**
     * @param key 16 bytes
     * @throws IllegalArgumentException if the key is not 16 bytes
     */
    public Aes128BlockCipher(byte[] key) {
        this.keySchedule = new AesKeySchedule(key);
    }

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    /** CIPHER(), Algorithm 1. */
    @Override
    public byte[] encryptBlock(byte[] plaintextBlock) {
        requireOneBlock(plaintextBlock);
        byte[] state = addRoundKey(plaintextBlock, INITIAL_ROUND);
        for (int round = 1; round < ROUNDS; round++) {
            state = AesSBox.subBytes(state);
            state = AesRoundOps.shiftRows(state);
            state = AesRoundOps.mixColumns(state);
            state = addRoundKey(state, round);
        }
        state = AesSBox.subBytes(state);
        state = AesRoundOps.shiftRows(state);
        return addRoundKey(state, ROUNDS);
    }

    /** INVCIPHER(), Algorithm 3. */
    @Override
    public byte[] decryptBlock(byte[] ciphertextBlock) {
        requireOneBlock(ciphertextBlock);
        byte[] state = addRoundKey(ciphertextBlock, ROUNDS);
        for (int round = ROUNDS - 1; round >= 1; round--) {
            state = AesRoundOps.inverseShiftRows(state);
            state = AesSBox.inverseSubBytes(state);
            state = addRoundKey(state, round);
            state = AesRoundOps.inverseMixColumns(state);
        }
        state = AesRoundOps.inverseShiftRows(state);
        state = AesSBox.inverseSubBytes(state);
        return addRoundKey(state, INITIAL_ROUND);
    }

    /** ADDROUNDKEY(), section 5.1.4: XORs the state with the round key; it is its own inverse. */
    private byte[] addRoundKey(byte[] state, int round) {
        return Bytes.xor(state, keySchedule.roundKey(round));
    }

    private static void requireOneBlock(byte[] block) {
        if (block.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("AES block must be " + BLOCK_SIZE + " bytes, got " + block.length);
        }
    }
}
