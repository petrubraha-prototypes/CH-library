package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

class CbcModeTest {

    private static final byte[] IV = Bytes.fromHex("0f1e2d3c");
    private final BlockCipher blockCipher = new ToyBlockCipher();

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 4, 7, 12 })
    void roundTripWithPkcs7(int length) {
        Cipher cbc = new CbcMode(blockCipher, IV, new Pkcs7Padding());
        byte[] plaintext = new byte[length];
        Arrays.fill(plaintext, (byte) 0x42);
        assertArrayEquals(plaintext, cbc.decrypt(cbc.encrypt(plaintext)));
    }

    @Test
    void chainsEachBlockToThePreviousCiphertext() {
        Cipher cbc = new CbcMode(blockCipher, IV, new NoPadding());
        byte[] firstPlaintext = Bytes.fromHex("00010203");
        byte[] secondPlaintext = Bytes.fromHex("04050607");
        byte[] firstCiphertext = blockCipher.encryptBlock(Bytes.xor(firstPlaintext, IV));
        byte[] secondCiphertext = blockCipher.encryptBlock(Bytes.xor(secondPlaintext, firstCiphertext));
        byte[] expected = Blocks.join(List.of(firstCiphertext, secondCiphertext));
        assertArrayEquals(expected, cbc.encrypt(Bytes.fromHex("0001020304050607")));
    }

    @Test
    void equalPlaintextBlocksGiveDifferentCiphertextBlocks() {
        Cipher cbc = new CbcMode(blockCipher, IV, new NoPadding());
        byte[] ciphertext = cbc.encrypt(Bytes.fromHex("aabbccdd aabbccdd"));
        byte[] firstBlock = Arrays.copyOfRange(ciphertext, 0, ToyBlockCipher.BLOCK_SIZE);
        byte[] secondBlock = Arrays.copyOfRange(ciphertext, ToyBlockCipher.BLOCK_SIZE, ciphertext.length);
        assertFalse(Arrays.equals(firstBlock, secondBlock));
    }

    @Test
    void differentIvsGiveDifferentCiphertexts() {
        byte[] plaintext = Bytes.fromHex("aabbccdd");
        byte[] first = new CbcMode(blockCipher, IV, new NoPadding()).encrypt(plaintext);
        byte[] second = new CbcMode(blockCipher, Bytes.fromHex("00000000"), new NoPadding()).encrypt(plaintext);
        assertFalse(Arrays.equals(first, second));
    }

    @Test
    void ivIsCopiedAtConstruction() {
        byte[] iv = IV.clone();
        Cipher cbc = new CbcMode(blockCipher, iv, new NoPadding());
        byte[] before = cbc.encrypt(Bytes.fromHex("aabbccdd"));
        iv[0] ^= 1;
        assertArrayEquals(before, cbc.encrypt(Bytes.fromHex("aabbccdd")));
    }

    @Test
    void rejectsIvOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class,
                () -> new CbcMode(blockCipher, new byte[3], new Pkcs7Padding()));
    }

    @Test
    void decryptRejectsPartialBlocks() {
        Cipher cbc = new CbcMode(blockCipher, IV, new Pkcs7Padding());
        assertThrows(IllegalArgumentException.class, () -> cbc.decrypt(new byte[5]));
    }

    /** NIST SP 800-38A, F.2.1 and F.2.2: CBC-AES128. */
    @Test
    void matchesNistSp80038aWithAes128() {
        Cipher cipher = new CbcMode(Sp80038aVectors.aes128(), Sp80038aVectors.INITIALIZATION_VECTOR, new NoPadding());
        byte[] ciphertext = Bytes.fromHex("7649abac8119b246cee98e9b12e9197d"
                + "5086cb9b507219ee95db113a917678b2"
                + "73bed6b8e3c1743b7116e69e22229516"
                + "3ff1caa1681fac09120eca307586e1a7");
        assertArrayEquals(ciphertext, cipher.encrypt(Sp80038aVectors.PLAINTEXT));
        assertArrayEquals(Sp80038aVectors.PLAINTEXT, cipher.decrypt(ciphertext));
    }
}
