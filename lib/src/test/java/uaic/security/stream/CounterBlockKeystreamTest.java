package uaic.security.stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class CounterBlockKeystreamTest {

    /** Each block is three copies of its counter, and every requested counter is recorded. */
    private static final class RecordingKeystream extends CounterBlockKeystream {
        private final List<Long> requestedCounters = new ArrayList<>();

        RecordingKeystream(long initialCounter) {
            super(initialCounter);
        }

        @Override
        protected byte[] generateBlock(long blockCounter) {
            requestedCounters.add(blockCounter);
            byte counterByte = (byte) blockCounter;
            return new byte[] { counterByte, counterByte, counterByte };
        }
    }

    @Test
    void emitsBlocksInCounterOrder() {
        RecordingKeystream keystream = new RecordingKeystream(5);
        byte[] output = new byte[7];
        keystream.fill(output);
        assertArrayEquals(new byte[] { 5, 5, 5, 6, 6, 6, 7 }, output);
    }

    @Test
    void generatesABlockOnlyWhenTheCurrentOneIsUsedUp() {
        RecordingKeystream keystream = new RecordingKeystream(0);
        keystream.fill(new byte[3]);
        assertEquals(List.of(0L), keystream.requestedCounters);
        keystream.nextByte();
        assertEquals(List.of(0L, 1L), keystream.requestedCounters);
    }

    @Test
    void generatesNothingBeforeTheFirstByteIsRequested() {
        RecordingKeystream keystream = new RecordingKeystream(0);
        assertEquals(List.of(), keystream.requestedCounters);
    }
}
