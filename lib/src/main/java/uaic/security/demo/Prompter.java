package uaic.security.demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Predicate;

/**
 * Asks the user for one value at a time and repeats the question, listing
 * the allowed values, until the answer is valid.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
class Prompter {
    private final BufferedReader reader;
    private final PrintStream output;

    /**
     * @param input  where the answers are read from
     * @param output where the questions are written
     */
    Prompter(InputStream input, PrintStream output) {
        this.reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        this.output = output;
    }

    /**
     * @param field         the name of the requested value
     * @param isValid       accepts the answers that may be returned
     * @param allowedValues what a valid answer looks like, shown after an invalid one
     * @return the first valid answer, without surrounding whitespace
     * @throws UsageException if the input ends before a valid answer
     */
    String ask(String field, Predicate<String> isValid, String allowedValues) {
        while (true) {
            output.print(field + ": ");
            output.flush();
            String answer = readLine(field).trim();
            if (isValid.test(answer)) {
                return answer;
            }
            output.println("Invalid " + field + ". Allowed: " + allowedValues);
        }
    }

    private String readLine(String field) {
        try {
            String line = reader.readLine();
            if (line == null) {
                throw new UsageException("Input ended before a " + field + " was given");
            }
            return line;
        } catch (IOException readFailure) {
            throw new UncheckedIOException(readFailure);
        }
    }
}
