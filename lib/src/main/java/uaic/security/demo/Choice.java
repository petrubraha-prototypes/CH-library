package uaic.security.demo;

import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * A value the user picks by typing its label, such as a cipher or a mode name.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
interface Choice {
    String SEPARATOR = ", ";

    /**
     * @return the word the user types to pick this value
     */
    String label();

    /**
     * Finds the option whose label matches, ignoring case.
     *
     * @param options the allowed values
     * @param label   what the user typed
     * @return the matching option, if any
     */
    static <T extends Choice> Optional<T> find(T[] options, String label) {
        return Arrays.stream(options)
                .filter(option -> option.label().equalsIgnoreCase(label.trim()))
                .findFirst();
    }

    /**
     * Lists the labels of the options for usage and error messages.
     *
     * @param options the allowed values
     * @return the labels, comma-separated
     */
    static String describe(Choice[] options) {
        return Arrays.stream(options).map(Choice::label).collect(Collectors.joining(SEPARATOR));
    }
}
