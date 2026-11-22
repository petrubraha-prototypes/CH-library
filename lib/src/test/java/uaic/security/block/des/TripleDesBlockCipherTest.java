package uaic.security.block.des;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.mode.CbcMode;
import uaic.security.mode.CfbMode;
import uaic.security.mode.EcbMode;
import uaic.security.mode.NoPadding;
import uaic.security.mode.OfbMode;
import uaic.security.mode.Pkcs7Padding;
import uaic.security.util.Bytes;

class TripleDesBlockCipherTest {

    private static final byte[] FIRST_KEY = Bytes.fromHex("0123456789ABCDEF");
    private static final byte[] SECOND_KEY = Bytes.fromHex("23456789ABCDEF01");
    private static final byte[] THIRD_KEY = Bytes.fromHex("456789ABCDEF0123");

    private static Cipher modeFor(String mode, BlockCipher blockCipher, byte[] initializationVector) {
        return switch (mode) {
            case "ecb" -> new EcbMode(blockCipher, new NoPadding());
            case "cbc" -> new CbcMode(blockCipher, initializationVector, new NoPadding());
            case "ofb" -> new OfbMode(blockCipher, initializationVector);
            case "cfb" -> new CfbMode(blockCipher, initializationVector);
            default -> throw new IllegalArgumentException("Unknown mode " + mode);
        };
    }

    /** NIST CAVP three-key multi-block message tests, run through the step 7 modes. */
    @ParameterizedTest(name = "{0} #{1}")
    @CsvFileSource(resources = "/cavp/tdes-mmt3.csv")
    void modesOfTripleDesMatchNistCavp(String mode, int count, String firstKeyHex, String secondKeyHex,
            String thirdKeyHex, String ivHex, String plaintextHex, String ciphertextHex) {
        BlockCipher tripleDes = new TripleDesBlockCipher(
                Bytes.fromHex(firstKeyHex), Bytes.fromHex(secondKeyHex), Bytes.fromHex(thirdKeyHex));
        byte[] initializationVector = ivHex == null ? null : Bytes.fromHex(ivHex);
        Cipher cipher = modeFor(mode, tripleDes, initializationVector);
        byte[] plaintext = Bytes.fromHex(plaintextHex);
        byte[] ciphertext = Bytes.fromHex(ciphertextHex);
        assertArrayEquals(ciphertext, cipher.encrypt(plaintext));
        assertArrayEquals(plaintext, cipher.decrypt(ciphertext));
    }

    /** The first NIST CAVP variable-plaintext vector, where KEY1 = KEY2 = KEY3. */
    @Test
    void equalKeysReduceToSingleDes() {
        byte[] key = Bytes.fromHex("0101010101010101");
        BlockCipher tripleDes = new TripleDesBlockCipher(key, key, key);
        byte[] plaintext = Bytes.fromHex("8000000000000000");
        assertArrayEquals(Bytes.fromHex("95f8a5e5dd31d900"), tripleDes.encryptBlock(plaintext));
        assertArrayEquals(new DesBlockCipher(key).encryptBlock(plaintext), tripleDes.encryptBlock(plaintext));
    }

    @Test
    void encryptIsEncryptDecryptEncrypt() {
        BlockCipher tripleDes = new TripleDesBlockCipher(FIRST_KEY, SECOND_KEY, THIRD_KEY);
        byte[] block = Bytes.fromHex("4E6F772069732074");
        byte[] afterFirst = new DesBlockCipher(FIRST_KEY).encryptBlock(block);
        byte[] afterSecond = new DesBlockCipher(SECOND_KEY).decryptBlock(afterFirst);
        byte[] expected = new DesBlockCipher(THIRD_KEY).encryptBlock(afterSecond);
        assertArrayEquals(expected, tripleDes.encryptBlock(block));
    }

    @Test
    void roundTripThroughCbcWithPkcs7() {
        BlockCipher tripleDes = new TripleDesBlockCipher(FIRST_KEY, SECOND_KEY, THIRD_KEY);
        Cipher cbc = new CbcMode(tripleDes, Bytes.fromHex("1234567890ABCDEF"), new Pkcs7Padding());
        byte[] message = Bytes.fromHex("546865207175666b2062726f776e20666f78");
        assertArrayEquals(message, cbc.decrypt(cbc.encrypt(message)));
    }

    @Test
    void blockSizeIsTheDesBlockSize() {
        assertEquals(8, new TripleDesBlockCipher(FIRST_KEY, SECOND_KEY, THIRD_KEY).blockSize());
    }

    @Test
    void rejectsKeyOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class,
                () -> new TripleDesBlockCipher(FIRST_KEY, new byte[7], THIRD_KEY));
    }
}
