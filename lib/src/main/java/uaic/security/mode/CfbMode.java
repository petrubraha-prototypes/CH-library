package uaic.security.mode;

import java.util.ArrayList;
import java.util.List;

import lombok.NonNull;
import uaic.security.block.BlockCipher;

/**
 * Cipher Feedback mode (NIST SP 800-38A, section 6.3) with full-block
 * segments, for example CFB128 for AES: each ciphertext block is fed back as
 * the next cipher input, {@code C_j = P_j XOR CIPH_K(C_(j-1))},
 * {@code C_0 = IV}. A final partial block uses only the leading bytes of its
 * output block.
 *
 * <p>
 * Both directions use only the forward cipher.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public class CfbMode implements BlockMode {
    private final BlockCipher blockCipher;
    private final byte[] initializationVector;

    /**
     * @param blockCipher          the block transform
     * @param initializationVector one block, unpredictable per message
     * @throws IllegalArgumentException if the IV is not one block long
     */
    public CfbMode(@NonNull BlockCipher blockCipher, @NonNull byte[] initializationVector) {
        Blocks.requireOneBlock(initializationVector, blockCipher.blockSize(), "CFB IV");
        this.blockCipher = blockCipher;
        this.initializationVector = initializationVector.clone();
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        List<byte[]> ciphertextSegments = new ArrayList<>();
        byte[] inputBlock = initializationVector;
        for (byte[] plaintextSegment : Blocks.split(plaintext, blockCipher.blockSize())) {
            byte[] outputBlock = blockCipher.encryptBlock(inputBlock);
            byte[] ciphertextSegment = Blocks.xorWithLeadingBytes(plaintextSegment, outputBlock);
            ciphertextSegments.add(ciphertextSegment);
            inputBlock = ciphertextSegment;
        }
        return Blocks.join(ciphertextSegments);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        List<byte[]> plaintextSegments = new ArrayList<>();
        byte[] inputBlock = initializationVector;
        for (byte[] ciphertextSegment : Blocks.split(ciphertext, blockCipher.blockSize())) {
            byte[] outputBlock = blockCipher.encryptBlock(inputBlock);
            plaintextSegments.add(Blocks.xorWithLeadingBytes(ciphertextSegment, outputBlock));
            inputBlock = ciphertextSegment;
        }
        return Blocks.join(plaintextSegments);
    }
}
