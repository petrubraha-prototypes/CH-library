package uaic.security.mode;

import java.util.ArrayList;
import java.util.List;

import lombok.NonNull;
import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

/**
 * Cipher Block Chaining mode (NIST SP 800-38A, section 6.2): pads the message
 * and XORs each plaintext block with the previous ciphertext block, or with
 * the IV for the first one, before encrypting it:
 * {@code C_j = CIPH_K(P_j XOR C_(j-1))}, {@code C_0 = IV}.
 *
 * <p>
 * The IV is fixed at construction and not included in the ciphertext.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public class CbcMode implements BlockMode {
    private final BlockCipher blockCipher;
    private final byte[] initializationVector;
    private final Padding padding;

    /**
     * @param blockCipher          the block transform
     * @param initializationVector one block, unpredictable per message
     * @param padding              fills the last block before encryption
     * @throws IllegalArgumentException if the IV is not one block long
     */
    public CbcMode(@NonNull BlockCipher blockCipher, @NonNull byte[] initializationVector,
            @NonNull Padding padding) {
        Blocks.requireOneBlock(initializationVector, blockCipher.blockSize(), "CBC IV");
        this.blockCipher = blockCipher;
        this.initializationVector = initializationVector.clone();
        this.padding = padding;
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        int blockSize = blockCipher.blockSize();
        byte[] paddedPlaintext = padding.pad(plaintext, blockSize);
        List<byte[]> ciphertextBlocks = new ArrayList<>();
        byte[] previousCiphertextBlock = initializationVector;
        for (byte[] plaintextBlock : Blocks.splitWhole(paddedPlaintext, blockSize)) {
            byte[] chainedBlock = Bytes.xor(plaintextBlock, previousCiphertextBlock);
            previousCiphertextBlock = blockCipher.encryptBlock(chainedBlock);
            ciphertextBlocks.add(previousCiphertextBlock);
        }
        return Blocks.join(ciphertextBlocks);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        int blockSize = blockCipher.blockSize();
        List<byte[]> plaintextBlocks = new ArrayList<>();
        byte[] previousCiphertextBlock = initializationVector;
        for (byte[] ciphertextBlock : Blocks.splitWhole(ciphertext, blockSize)) {
            byte[] chainedBlock = blockCipher.decryptBlock(ciphertextBlock);
            plaintextBlocks.add(Bytes.xor(chainedBlock, previousCiphertextBlock));
            previousCiphertextBlock = ciphertextBlock;
        }
        byte[] paddedPlaintext = Blocks.join(plaintextBlocks);
        return padding.unpad(paddedPlaintext, blockSize);
    }
}
