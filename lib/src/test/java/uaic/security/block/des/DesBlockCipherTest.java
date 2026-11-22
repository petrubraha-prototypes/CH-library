package uaic.security.block.des;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

class DesBlockCipherTest {

    private static final byte[] KEY = Bytes.fromHex("133457799BBCDFF1");
    private static final byte[] BLOCK = Bytes.fromHex("0123456789ABCDEF");

    /** All 235 single-DES vectors of the NIST CAVP ECB known-answer tests. */
    @ParameterizedTest(name = "{0} #{1}")
    @CsvFileSource(resources = "/cavp/des-ecb-kat.csv")
    void encryptMatchesNistCavp(String file, int count, String keyHex, String plaintextHex, String ciphertextHex) {
        BlockCipher des = new DesBlockCipher(Bytes.fromHex(keyHex));
        assertArrayEquals(Bytes.fromHex(ciphertextHex), des.encryptBlock(Bytes.fromHex(plaintextHex)));
    }

    @ParameterizedTest(name = "{0} #{1}")
    @CsvFileSource(resources = "/cavp/des-ecb-kat.csv")
    void decryptMatchesNistCavp(String file, int count, String keyHex, String plaintextHex, String ciphertextHex) {
        BlockCipher des = new DesBlockCipher(Bytes.fromHex(keyHex));
        assertArrayEquals(Bytes.fromHex(plaintextHex), des.decryptBlock(Bytes.fromHex(ciphertextHex)));
    }

    @Test
    void roundTrip() {
        BlockCipher des = new DesBlockCipher(KEY);
        assertArrayEquals(BLOCK, des.decryptBlock(des.encryptBlock(BLOCK)));
    }

    /** Encrypting twice under a weak key (NIST SP 800-67 Rev. 2, section 3.3.2) is the identity. */
    @Test
    void weakKeyIsItsOwnInverse() {
        BlockCipher des = new DesBlockCipher(Bytes.fromHex("E0E0E0E0F1F1F1F1"));
        assertArrayEquals(BLOCK, des.encryptBlock(des.encryptBlock(BLOCK)));
    }

    /** Encrypting under one key of a semi-weak pair undoes encryption under the other. */
    @Test
    void semiWeakKeysUndoEachOther() {
        BlockCipher first = new DesBlockCipher(Bytes.fromHex("01FE01FE01FE01FE"));
        BlockCipher second = new DesBlockCipher(Bytes.fromHex("FE01FE01FE01FE01"));
        assertArrayEquals(BLOCK, second.encryptBlock(first.encryptBlock(BLOCK)));
    }

    @Test
    void blockSizeIsEightBytes() {
        assertEquals(8, new DesBlockCipher(KEY).blockSize());
    }

    @Test
    void rejectsBlockOfTheWrongLength() {
        BlockCipher des = new DesBlockCipher(KEY);
        assertThrows(IllegalArgumentException.class, () -> des.encryptBlock(new byte[16]));
    }

    @Test
    void rejectsKeyOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> new DesBlockCipher(new byte[16]));
    }
}
