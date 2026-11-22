package uaic.security.demo;

import java.util.Arrays;

import lombok.experimental.UtilityClass;
import uaic.security.Cipher;
import uaic.security.block.BlockCipher;
import uaic.security.block.aes.Aes128BlockCipher;
import uaic.security.block.des.DesBlockCipher;
import uaic.security.block.des.TripleDesBlockCipher;
import uaic.security.classic.AffineCipher;
import uaic.security.classic.CharCipher;
import uaic.security.classic.PermutationCipher;
import uaic.security.classic.SubstitutionCipher;
import uaic.security.classic.TextCipherAdapter;
import uaic.security.classic.TranspositionCipher;
import uaic.security.classic.VigenereCipher;
import uaic.security.mode.CbcMode;
import uaic.security.mode.CfbMode;
import uaic.security.mode.CtrMode;
import uaic.security.mode.DctrMode;
import uaic.security.mode.EcbMode;
import uaic.security.mode.OfbMode;
import uaic.security.mode.Pkcs7Padding;
import uaic.security.stream.ChaCha20Keystream;
import uaic.security.stream.Rc4Keystream;
import uaic.security.stream.Salsa20Keystream;
import uaic.security.stream.StreamCipher;
import uaic.security.util.Bytes;

/**
 * Builds the configured {@link Cipher} from the user's choices: classical
 * ciphers behind a {@link TextCipherAdapter}, stream ciphers directly and
 * block ciphers wrapped in the chosen mode, with PKCS#7 padding for ECB and
 * CBC.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
class CipherFactory {
    private static final String NUMBER_SEPARATOR = ",";
    private static final int AFFINE_KEY_PARTS = 2;
    private static final int DES_KEY_LENGTH = 8;
    private static final int TRIPLE_DES_KEY_COUNT = 3;
    /** RFC 8439, section 2.4.2 starts its encryption example at block counter 1. */
    private static final int CHACHA20_INITIAL_COUNTER = 1;

    /**
     * @param request the parsed choices
     * @return the cipher ready to encrypt or decrypt
     * @throws IllegalArgumentException if a key, nonce or IV is malformed or has the wrong length
     */
    static Cipher create(CipherRequest request) {
        String key = request.key();
        return switch (request.cipher()) {
            case AFFINE -> new TextCipherAdapter(affineCipher(key));
            case SUBSTITUTION -> new TextCipherAdapter(new SubstitutionCipher(key));
            case PERMUTATION -> new TextCipherAdapter(new PermutationCipher(parseNumbers(key)));
            case TRANSPOSITION -> new TextCipherAdapter(new TranspositionCipher(key));
            case VIGENERE -> new TextCipherAdapter(new VigenereCipher(key));
            case RC4 -> rc4(Bytes.fromHex(key));
            case SALSA20 -> salsa20(Bytes.fromHex(key), Bytes.fromHex(request.nonceOrIv()));
            case CHACHA20 -> chaCha20(Bytes.fromHex(key), Bytes.fromHex(request.nonceOrIv()));
            case DES -> blockMode(new DesBlockCipher(Bytes.fromHex(key)), request);
            case TRIPLE_DES -> blockMode(tripleDes(Bytes.fromHex(key)), request);
            case AES128 -> blockMode(new Aes128BlockCipher(Bytes.fromHex(key)), request);
        };
    }

    private static CharCipher affineCipher(String key) {
        int[] coefficients = parseNumbers(key);
        if (coefficients.length != AFFINE_KEY_PARTS) {
            throw new IllegalArgumentException("Affine key must be two integers a,b such as 5,8, got " + key);
        }
        return new AffineCipher(coefficients[0], coefficients[1]);
    }

    private static int[] parseNumbers(String key) {
        try {
            return Arrays.stream(key.split(NUMBER_SEPARATOR)).map(String::trim).mapToInt(Integer::parseInt).toArray();
        } catch (NumberFormatException notANumber) {
            throw new IllegalArgumentException("Key must be comma-separated integers, got " + key);
        }
    }

    private static Cipher rc4(byte[] key) {
        return new StreamCipher(() -> new Rc4Keystream(key));
    }

    private static Cipher salsa20(byte[] key, byte[] nonce) {
        return new StreamCipher(() -> new Salsa20Keystream(key, nonce));
    }

    private static Cipher chaCha20(byte[] key, byte[] nonce) {
        return new StreamCipher(() -> new ChaCha20Keystream(key, nonce, CHACHA20_INITIAL_COUNTER));
    }

    /** The 3DES key bundle is K1 | K2 | K3, 24 bytes. */
    private static BlockCipher tripleDes(byte[] keyBundle) {
        int bundleLength = DES_KEY_LENGTH * TRIPLE_DES_KEY_COUNT;
        if (keyBundle.length != bundleLength) {
            throw new IllegalArgumentException("3DES key bundle must be " + bundleLength + " bytes (K1 | K2 | K3), got "
                    + keyBundle.length);
        }
        byte[] firstKey = Arrays.copyOfRange(keyBundle, 0, DES_KEY_LENGTH);
        byte[] secondKey = Arrays.copyOfRange(keyBundle, DES_KEY_LENGTH, 2 * DES_KEY_LENGTH);
        byte[] thirdKey = Arrays.copyOfRange(keyBundle, 2 * DES_KEY_LENGTH, bundleLength);
        return new TripleDesBlockCipher(firstKey, secondKey, thirdKey);
    }

    private static Cipher blockMode(BlockCipher blockCipher, CipherRequest request) {
        return switch (request.mode()) {
            case ECB -> new EcbMode(blockCipher, new Pkcs7Padding());
            case CBC -> new CbcMode(blockCipher, initializationVector(request), new Pkcs7Padding());
            case CTR -> new CtrMode(blockCipher, initializationVector(request));
            case DCTR -> new DctrMode(blockCipher);
            case OFB -> new OfbMode(blockCipher, initializationVector(request));
            case CFB -> new CfbMode(blockCipher, initializationVector(request));
        };
    }

    private static byte[] initializationVector(CipherRequest request) {
        return Bytes.fromHex(request.nonceOrIv());
    }
}
