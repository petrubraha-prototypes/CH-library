package uaic.security.demo;

import java.io.InputStream;
import java.io.PrintStream;

import lombok.experimental.UtilityClass;
import uaic.security.Cipher;

/**
 * Command-line demo: lets the user pick any implemented cipher, configure
 * it and encrypt or decrypt one input. It only reads the choices, asks
 * {@link CipherFactory} for the cipher and prints the result; it contains no
 * cipher logic.
 *
 * <p>
 * Usage: {@code <cipher> <op> <key> [iv/nonce] [mode] <input>}. Missing
 * fields are asked for interactively.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
@UtilityClass
public class CryptoDemo {
    static final int SUCCESS = 0;
    static final int INVALID_VALUE = 1;
    static final int USAGE_ERROR = 2;

    private static final String USAGE = String.join(System.lineSeparator(),
            "Usage: <cipher> <op> <key> [iv/nonce] [mode] <input>",
            "  cipher: " + Choice.describe(CipherName.values()),
            "  op:     " + Choice.describe(Operation.values()),
            "  mode:   " + Choice.describe(ModeName.values()) + " (block ciphers only)",
            "  nonce:  salsa20 (8 bytes) and chacha20 (12 bytes) only",
            "  iv:     cbc, ctr, ofb and cfb only",
            "  key, iv/nonce and input are hex for byte ciphers and plain text for classical ciphers",
            "Example: aes128 encrypt 2b7e151628aed2a6abf7158809cf4f3c 000102030405060708090a0b0c0d0e0f cbc"
                    + " 6bc1bee22e409f96e93d7e117393172a");

    /**
     * Runs the demo on the console and exits with a non-zero status on error.
     *
     * @param arguments the request fields, possibly none
     */
    public static void main(String[] arguments) {
        int status = run(arguments, System.in, System.out, System.err);
        if (status != SUCCESS) {
            System.exit(status);
        }
    }

    /**
     * Runs one request.
     *
     * @return {@link #SUCCESS}, {@link #USAGE_ERROR} for invalid arguments or
     *         {@link #INVALID_VALUE} when the cipher rejects a key, IV or input
     */
    static int run(String[] arguments, InputStream input, PrintStream output, PrintStream errors) {
        try {
            RequestReader reader = new RequestReader(arguments, new Prompter(input, output));
            CipherRequest request = reader.read();
            output.println(execute(request));
            return SUCCESS;
        } catch (UsageException invalidUsage) {
            errors.println(invalidUsage.getMessage());
            errors.println(USAGE);
            return USAGE_ERROR;
        } catch (IllegalArgumentException invalidValue) {
            errors.println(invalidValue.getMessage());
            return INVALID_VALUE;
        }
    }

    private static String execute(CipherRequest request) {
        DataFormat format = request.cipher().family().dataFormat();
        Cipher cipher = CipherFactory.create(request);
        byte[] data = format.parse(request.input());
        byte[] result = request.operation().apply(cipher, data);
        return format.format(result);
    }
}
