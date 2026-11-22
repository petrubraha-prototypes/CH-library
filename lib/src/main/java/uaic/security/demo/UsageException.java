package uaic.security.demo;

/**
 * Signals that the command-line arguments, or the answers to the prompts,
 * cannot form a valid demo request.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
class UsageException extends RuntimeException {
    UsageException(String message) {
        super(message);
    }
}
