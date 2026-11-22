package uaic.security.mode;

import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

/**
 * A trivial, invertible 4-byte block transform used to test the modes in
 * isolation: rotate the bytes one position left, then XOR with the key.
 */
final class ToyBlockCipher implements BlockCipher {
    static final int BLOCK_SIZE = 4;
    private static final byte[] KEY = Bytes.fromHex("a5c3e10f");

    @Override
    public int blockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public byte[] encryptBlock(byte[] plaintextBlock) {
        byte[] rotated = new byte[BLOCK_SIZE];
        for (int index = 0; index < BLOCK_SIZE; index++) {
            rotated[index] = plaintextBlock[(index + 1) % BLOCK_SIZE];
        }
        return Bytes.xor(rotated, KEY);
    }

    @Override
    public byte[] decryptBlock(byte[] ciphertextBlock) {
        byte[] rotated = Bytes.xor(ciphertextBlock, KEY);
        byte[] original = new byte[BLOCK_SIZE];
        for (int index = 0; index < BLOCK_SIZE; index++) {
            original[(index + 1) % BLOCK_SIZE] = rotated[index];
        }
        return original;
    }
}
