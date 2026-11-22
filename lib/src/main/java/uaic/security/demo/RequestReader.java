package uaic.security.demo;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.function.Predicate;

/**
 * Collects a {@link CipherRequest} field by field, in the order
 * {@code <cipher> <op> <key> [iv/nonce] [mode] <input>}. Each field comes
 * from the next command-line argument; once the arguments run out, the
 * remaining fields are asked for interactively.
 *
 * <p>
 * An invalid argument is a usage error. An invalid interactive answer is
 * asked for again. When prompting, a block cipher's mode is asked before its
 * IV, because only the mode tells whether an IV is needed.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
class RequestReader {
    private static final String CIPHER_FIELD = "cipher";
    private static final String OPERATION_FIELD = "operation";
    private static final String MODE_FIELD = "mode";
    private static final String KEY_FIELD = "key";
    private static final String NONCE_FIELD = "nonce";
    private static final String IV_FIELD = "IV";
    private static final String INPUT_FIELD = "input";

    private final Deque<String> remainingArguments;
    private final Prompter prompter;

    /**
     * @param arguments the command-line arguments, possibly fewer than needed
     * @param prompter  asks for the fields the arguments do not provide
     */
    RequestReader(String[] arguments, Prompter prompter) {
        this.remainingArguments = new ArrayDeque<>(Arrays.asList(arguments));
        this.prompter = prompter;
    }

    /**
     * @return the complete request
     * @throws UsageException if an argument is invalid, superfluous or the input ends early
     */
    CipherRequest read() {
        CipherName cipher = readChoice(CIPHER_FIELD, CipherName.values());
        Operation operation = readChoice(OPERATION_FIELD, Operation.values());
        CipherFamily family = cipher.family();
        String key = readData(KEY_FIELD, family.dataFormat());
        String nonceOrIv = null;
        ModeName mode = null;
        if (family.requiresNonce()) {
            nonceOrIv = readData(NONCE_FIELD, DataFormat.HEX);
        }
        if (family.requiresMode()) {
            BlockSettings blockSettings = readBlockSettings();
            nonceOrIv = blockSettings.initializationVector();
            mode = blockSettings.mode();
        }
        String input = readData(INPUT_FIELD, family.dataFormat());
        rejectExtraArguments();
        return new CipherRequest(cipher, operation, key, nonceOrIv, mode, input);
    }

    /** The mode of a block cipher and its IV, or {@code null} when the mode takes none. */
    private record BlockSettings(ModeName mode, String initializationVector) {
    }

    /** Reads the optional IV and the mode; on the command line the IV comes first. */
    private BlockSettings readBlockSettings() {
        boolean ivArgumentFirst = !remainingArguments.isEmpty() && !isMode(remainingArguments.peek());
        if (ivArgumentFirst) {
            String initializationVector = readData(IV_FIELD, DataFormat.HEX);
            ModeName mode = readChoice(MODE_FIELD, ModeName.values());
            if (!mode.requiresIv()) {
                throw new UsageException("Mode " + mode.label() + " takes no IV");
            }
            return new BlockSettings(mode, initializationVector);
        }
        ModeName mode = readChoice(MODE_FIELD, ModeName.values());
        String initializationVector = mode.requiresIv() ? readData(IV_FIELD, DataFormat.HEX) : null;
        return new BlockSettings(mode, initializationVector);
    }

    private static boolean isMode(String text) {
        return Choice.find(ModeName.values(), text).isPresent();
    }

    private <T extends Choice> T readChoice(String field, T[] options) {
        Predicate<String> isOption = text -> Choice.find(options, text).isPresent();
        String label = readValue(field, isOption, Choice.describe(options));
        return Choice.find(options, label).orElseThrow();
    }

    private String readData(String field, DataFormat format) {
        return readValue(field + " (" + format.description() + ")", format::accepts, format.description());
    }

    private String readValue(String field, Predicate<String> isValid, String allowedValues) {
        if (remainingArguments.isEmpty()) {
            return prompter.ask(field, isValid, allowedValues);
        }
        String argument = remainingArguments.poll();
        if (!isValid.test(argument)) {
            throw new UsageException("Invalid " + field + " '" + argument + "'. Allowed: " + allowedValues);
        }
        return argument;
    }

    private void rejectExtraArguments() {
        if (!remainingArguments.isEmpty()) {
            throw new UsageException("Unexpected extra arguments: " + String.join(" ", remainingArguments));
        }
    }
}
