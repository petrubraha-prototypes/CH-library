package uaic.security.block.aes;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import uaic.security.block.BlockCipher;
import uaic.security.util.Bytes;

class Aes128BlockCipherTest {

    private static final byte[] APPENDIX_KEY = Bytes.fromHex("2b7e151628aed2a6abf7158809cf4f3c");

    /** FIPS 197 (2023 update), Appendix B. */
    @Test
    void encryptMatchesTheFips197CipherExample() {
        BlockCipher aes = new Aes128BlockCipher(APPENDIX_KEY);
        byte[] input = Bytes.fromHex("3243f6a8885a308d313198a2e0370734");
        assertArrayEquals(Bytes.fromHex("3925841d02dc09fbdc118597196a0b32"), aes.encryptBlock(input));
    }

    @Test
    void decryptInvertsTheFips197CipherExample() {
        BlockCipher aes = new Aes128BlockCipher(APPENDIX_KEY);
        byte[] output = Bytes.fromHex("3925841d02dc09fbdc118597196a0b32");
        assertArrayEquals(Bytes.fromHex("3243f6a8885a308d313198a2e0370734"), aes.decryptBlock(output));
    }

    /** All 284 AES-128 vectors of the NIST CAVP ECB known-answer tests (GFSbox, KeySbox, VarKey, VarTxt). */
    @ParameterizedTest(name = "{0} #{1}")
    @CsvFileSource(resources = "/cavp/aes128-ecb-kat.csv")
    void encryptMatchesNistCavp(String file, int count, String keyHex, String plaintextHex, String ciphertextHex) {
        BlockCipher aes = new Aes128BlockCipher(Bytes.fromHex(keyHex));
        assertArrayEquals(Bytes.fromHex(ciphertextHex), aes.encryptBlock(Bytes.fromHex(plaintextHex)));
    }

    @ParameterizedTest(name = "{0} #{1}")
    @CsvFileSource(resources = "/cavp/aes128-ecb-kat.csv")
    void decryptMatchesNistCavp(String file, int count, String keyHex, String plaintextHex, String ciphertextHex) {
        BlockCipher aes = new Aes128BlockCipher(Bytes.fromHex(keyHex));
        assertArrayEquals(Bytes.fromHex(plaintextHex), aes.decryptBlock(Bytes.fromHex(ciphertextHex)));
    }

    @Test
    void roundTrip() {
        BlockCipher aes = new Aes128BlockCipher(APPENDIX_KEY);
        byte[] block = Bytes.fromHex("00112233445566778899aabbccddeeff");
        assertArrayEquals(block, aes.decryptBlock(aes.encryptBlock(block)));
    }

    @Test
    void blockSizeIsSixteenBytes() {
        assertEquals(16, new Aes128BlockCipher(APPENDIX_KEY).blockSize());
    }

    @Test
    void rejectsBlockOfTheWrongLength() {
        BlockCipher aes = new Aes128BlockCipher(APPENDIX_KEY);
        assertThrows(IllegalArgumentException.class, () -> aes.encryptBlock(new byte[8]));
        assertThrows(IllegalArgumentException.class, () -> aes.decryptBlock(new byte[17]));
    }

    @Test
    void rejectsKeyOfTheWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> new Aes128BlockCipher(new byte[32]));
    }
}
