package uaic.security.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

class CfbModeTest {

    private static final byte[] IV = Bytes.fromHex("0f1e2d3c");
    private final BlockCipher blockCipher = new ToyBlockCipher();

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 4, 10 })
    void roundTripWithoutPadding(int length) {
        Cipher cfb = new CfbMode(blockCipher, IV);
        byte[] plaintext = new byte[length];
        for (int index = 0; index < length; index++) {
            plaintext[index] = (byte) (3 * index);
        }
        assertArrayEquals(plaintext, cfb.decrypt(cfb.encrypt(plaintext)));
    }

    @Test
    void feedsEachCiphertextBlockIntoTheNextCipherInput() {
        Cipher cfb = new CfbMode(blockCipher, IV);
        byte[] firstPlaintext = Bytes.fromHex("00010203");
        byte[] secondPlaintext = Bytes.fromHex("0405");
        byte[] firstCiphertext = Bytes.xor(firstPlaintext, blockCipher.encryptBlock(IV));
        byte[] secondCiphertext = Blocks.xorWithLeadingBytes(secondPlaintext,
                blockCipher.encryptBlock(firstCiphertext));
        byte[] expected = Blocks.join(List.of(firstCiphertext, secondCiphertext));
        assertArrayEquals(expected, cfb.encrypt(Bytes.fromHex("000102030405")));
    }

    @Test
    void decryptionUsesOnlyTheForwardCipher() {
        BlockCipher forwardOnly = new BlockCipher() {
            @Override
            public int blockSize() {
                return blockCipher.blockSize();
            }

            @Override
            public byte[] encryptBlock(byte[] plaintextBlock) {
                return blockCipher.encryptBlock(plaintextBlock);
            }

            @Override
            public byte[] decryptBlock(byte[] ciphertextBlock) {
                throw new AssertionError("CFB must not call the inverse cipher");
            }
        };
        Cipher cfb = new CfbMode(forwardOnly, IV);
        byte[] plaintext = Bytes.fromHex("0011223344");
        assertArrayEquals(plaintext, cfb.decrypt(cfb.encrypt(plaintext)));
    }

    @Test
    void rejectsIvOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> new CfbMode(blockCipher, new byte[2]));
    }
}
