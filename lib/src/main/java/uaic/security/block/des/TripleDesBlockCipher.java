package uaic.security.block.des;

import uaic.security.block.BlockCipher;

/**
 * Triple DES (TDEA) in the encrypt-decrypt-encrypt form of NIST SP 800-67
 * Rev. 2, section 3.1, built from three {@link DesBlockCipher} instances:
 * {@code O = E_K3(D_K2(E_K1(d)))} forward and
 * {@code O = D_K1(E_K2(D_K3(d)))} inverse.
 *
 * <p>
 * With {@code K1 = K2 = K3} the middle steps cancel and it reduces to single
 * DES, which is why EDE was chosen.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong> NIST SP 800-131A
 * Rev. 2 disallows TDEA for encryption after 2023.
 */
public class TripleDesBlockCipher implements BlockCipher {
    private final DesBlockCipher firstDes;
    private final DesBlockCipher secondDes;
    private final DesBlockCipher thirdDes;

    /**
     * @param firstKey  K1, 8 bytes
     * @param secondKey K2, 8 bytes
     * @param thirdKey  K3, 8 bytes
     * @throws IllegalArgumentException if a key is not 8 bytes
     */
    public TripleDesBlockCipher(byte[] firstKey, byte[] secondKey, byte[] thirdKey) {
        this.firstDes = new DesBlockCipher(firstKey);
        this.secondDes = new DesBlockCipher(secondKey);
        this.thirdDes = new DesBlockCipher(thirdKey);
    }

    @Override
    public int blockSize() {
        return firstDes.blockSize();
    }

    @Override
    public byte[] encryptBlock(byte[] plaintextBlock) {
        byte[] afterFirst = firstDes.encryptBlock(plaintextBlock);
        byte[] afterSecond = secondDes.decryptBlock(afterFirst);
        return thirdDes.encryptBlock(afterSecond);
    }

    @Override
    public byte[] decryptBlock(byte[] ciphertextBlock) {
        byte[] afterThird = thirdDes.decryptBlock(ciphertextBlock);
        byte[] afterSecond = secondDes.encryptBlock(afterThird);
        return firstDes.decryptBlock(afterSecond);
    }
}
