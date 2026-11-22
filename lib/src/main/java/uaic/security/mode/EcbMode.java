package uaic.security.mode;

import java.util.List;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import uaic.security.block.BlockCipher;

/**
 * Electronic Codebook mode (NIST SP 800-38A, section 6.1): pads the message
 * and encrypts every block independently, {@code C_j = CIPH_K(P_j)}.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> Equal plaintext
 * blocks give equal ciphertext blocks, so ECB leaks the structure of the
 * message; it is included for contrast with the other modes.
 */
@RequiredArgsConstructor
public class EcbMode implements BlockMode {
    @NonNull
    private final BlockCipher blockCipher;
    @NonNull
    private final Padding padding;

    @Override
    public byte[] encrypt(byte[] plaintext) {
        int blockSize = blockCipher.blockSize();
        byte[] paddedPlaintext = padding.pad(plaintext, blockSize);
        List<byte[]> ciphertextBlocks = Blocks.splitWhole(paddedPlaintext, blockSize).stream()
                .map(blockCipher::encryptBlock)
                .toList();
        return Blocks.join(ciphertextBlocks);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        int blockSize = blockCipher.blockSize();
        List<byte[]> plaintextBlocks = Blocks.splitWhole(ciphertext, blockSize).stream()
                .map(blockCipher::decryptBlock)
                .toList();
        byte[] paddedPlaintext = Blocks.join(plaintextBlocks);
        return padding.unpad(paddedPlaintext, blockSize);
    }
}
