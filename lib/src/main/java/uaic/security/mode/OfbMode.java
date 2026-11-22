package uaic.security.mode;

import java.util.ArrayList;
import java.util.List;

import lombok.NonNull;
import uaic.security.block.BlockCipher;

/**
 * Output Feedback mode (NIST SP 800-38A, section 6.4): repeatedly encrypts
 * the IV to form a keystream that never depends on the data,
 * {@code O_j = CIPH_K(O_(j-1))}, {@code O_0 = IV}, and
 * {@code C_j = P_j XOR O_j}. A final partial block uses only the leading
 * bytes of its output block.
 *
 * <p>
 * Encryption and decryption are the same operation.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
public class OfbMode implements BlockMode {
    private final BlockCipher blockCipher;
    private final byte[] initializationVector;

    /**
     * @param blockCipher          the block transform
     * @param initializationVector one block, unique per message
     * @throws IllegalArgumentException if the IV is not one block long
     */
    public OfbMode(@NonNull BlockCipher blockCipher, @NonNull byte[] initializationVector) {
        Blocks.requireOneBlock(initializationVector, blockCipher.blockSize(), "OFB IV");
        this.blockCipher = blockCipher;
        this.initializationVector = initializationVector.clone();
    }

    @Override
    public byte[] encrypt(byte[] plaintext) {
        return xorWithOutputFeedback(plaintext);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        return xorWithOutputFeedback(ciphertext);
    }

    private byte[] xorWithOutputFeedback(byte[] data) {
        List<byte[]> outputSegments = new ArrayList<>();
        byte[] outputBlock = initializationVector;
        for (byte[] segment : Blocks.split(data, blockCipher.blockSize())) {
            outputBlock = blockCipher.encryptBlock(outputBlock);
            outputSegments.add(Blocks.xorWithLeadingBytes(segment, outputBlock));
        }
        return Blocks.join(outputSegments);
    }
}
