package uaic.security.stream;

/**
 * Hands out keystream bytes one at a time from a sequence of blocks, where
 * block number {@code n} is produced from the counter value
 * {@code initialCounter + n}. Subclasses only define how one block is
 * computed from a counter.
 *
 * <p>
 * Salsa20 and ChaCha20 share this counter-based structure, so the buffering
 * lives here once.
 *
 * <p>
 * <strong>Educational, insecure, not for production.</strong>
 */
abstract class CounterBlockKeystream implements Keystream {
    private byte[] currentBlock = new byte[0];
    private int positionInBlock;
    private long nextBlockCounter;

    /**
     * @param initialCounter the counter value of the first block
     */
    protected CounterBlockKeystream(long initialCounter) {
        this.nextBlockCounter = initialCounter;
    }

    @Override
    public final byte nextByte() {
        if (positionInBlock == currentBlock.length) {
            currentBlock = generateBlock(nextBlockCounter);
            nextBlockCounter++;
            positionInBlock = 0;
        }
        byte keystreamByte = currentBlock[positionInBlock];
        positionInBlock++;
        return keystreamByte;
    }

    /**
     * Computes one keystream block.
     *
     * @param blockCounter the position of the block in the keystream
     * @return the keystream bytes of that block
     */
    protected abstract byte[] generateBlock(long blockCounter);
}
