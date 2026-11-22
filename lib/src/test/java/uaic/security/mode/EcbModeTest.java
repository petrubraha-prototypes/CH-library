package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

class EcbModeTest {

    private final BlockCipher blockCipher = new ToyBlockCipher();

    private static byte[] counting(int length) {
        byte[] data = new byte[length];
        for (int index = 0; index < length; index++) {
            data[index] = (byte) index;
        }
        return data;
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 3, 4, 5, 13 })
    void roundTripWithPkcs7(int length) {
        Cipher ecb = new EcbMode(blockCipher, new Pkcs7Padding());
        byte[] plaintext = counting(length);
        assertArrayEquals(plaintext, ecb.decrypt(ecb.encrypt(plaintext)));
    }

    @Test
    void encryptsEachBlockIndependently() {
        Cipher ecb = new EcbMode(blockCipher, new NoPadding());
        byte[] firstBlock = Bytes.fromHex("00010203");
        byte[] secondBlock = Bytes.fromHex("04050607");
        byte[] expected = Blocks.join(List.of(
                blockCipher.encryptBlock(firstBlock), blockCipher.encryptBlock(secondBlock)));
        assertArrayEquals(expected, ecb.encrypt(Bytes.fromHex("0001020304050607")));
    }

    @Test
    void equalPlaintextBlocksGiveEqualCiphertextBlocks() {
        Cipher ecb = new EcbMode(blockCipher, new NoPadding());
        byte[] ciphertext = ecb.encrypt(Bytes.fromHex("aabbccdd aabbccdd"));
        byte[] firstBlock = Arrays.copyOfRange(ciphertext, 0, ToyBlockCipher.BLOCK_SIZE);
        byte[] secondBlock = Arrays.copyOfRange(ciphertext, ToyBlockCipher.BLOCK_SIZE, ciphertext.length);
        assertArrayEquals(firstBlock, secondBlock);
    }

    @Test
    void pkcs7AddsAFullBlockToAlignedMessages() {
        Cipher ecb = new EcbMode(blockCipher, new Pkcs7Padding());
        assertEquals(2 * ToyBlockCipher.BLOCK_SIZE, ecb.encrypt(counting(ToyBlockCipher.BLOCK_SIZE)).length);
    }

    @Test
    void noPaddingRejectsPartialBlocks() {
        Cipher ecb = new EcbMode(blockCipher, new NoPadding());
        assertThrows(IllegalArgumentException.class, () -> ecb.encrypt(counting(5)));
    }

    @Test
    void decryptRejectsPartialBlocks() {
        Cipher ecb = new EcbMode(blockCipher, new Pkcs7Padding());
        assertThrows(IllegalArgumentException.class, () -> ecb.decrypt(counting(6)));
    }

    /** NIST SP 800-38A, F.1.1 and F.1.2: ECB-AES128. */
    @Test
    void matchesNistSp80038aWithAes128() {
        Cipher cipher = new EcbMode(Sp80038aVectors.aes128(), new NoPadding());
        byte[] ciphertext = Bytes.fromHex("3ad77bb40d7a3660a89ecaf32466ef97"
                + "f5d3d58503b9699de785895a96fdbaaf"
                + "43b1cd7f598ece23881b00e3ed030688"
                + "7b0c785e27e8ad3f8223207104725dd4");
        assertArrayEquals(ciphertext, cipher.encrypt(Sp80038aVectors.PLAINTEXT));
        assertArrayEquals(Sp80038aVectors.PLAINTEXT, cipher.decrypt(ciphertext));
    }
}
