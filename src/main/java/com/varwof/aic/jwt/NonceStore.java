package com.varwof.aic.jwt;

import com.varwof.aic.AicException;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Nonce store for DA nonce / jti replay prevention.
 * Mirrors Go {@code types/aicjwt/nonce.go}. In-memory for reference
 * deployments; production should use a persistent store.
 */
public final class NonceStore {
    private NonceStore() {
    }

    public interface Store {
        /** Records the nonce, rejecting duplicates. */
        void checkAndAdd(String nonce);
    }

    /** Replayed DA nonce. */
    public static final class NonceReuseException extends AicException {
        public final String nonce;

        public NonceReuseException(String nonce) {
            super("nonce reuse: " + nonce);
            this.nonce = nonce;
        }
    }

    /**
     * In-memory {@link Store} with a TTL and a size cap so it cannot grow
     * unbounded.
     */
    public static final class MemNonceStore implements Store {
        private static final long DEFAULT_TTL_NANOS = Duration.ofDays(1).toNanos();
        private static final int DEFAULT_MAX_ENTRIES = 1_000_000;
        private static final long SWEEP_INTERVAL = 256;

        private final Map<String, Long> seen = new ConcurrentHashMap<>(); // nonce -> expiry (nanotime)
        private final long ttlNanos;
        private final int maxEntries;
        private final AtomicLong inserts = new AtomicLong();

        /** Default TTL (1 day, matching the max token lifetime) and entry cap. */
        public MemNonceStore() {
            this(Duration.ofDays(1), DEFAULT_MAX_ENTRIES);
        }

        public MemNonceStore(Duration ttl, int maxEntries) {
            this.ttlNanos = ttl == null || ttl.isZero() || ttl.isNegative()
                    ? DEFAULT_TTL_NANOS : ttl.toNanos();
            this.maxEntries = maxEntries <= 0 ? DEFAULT_MAX_ENTRIES : maxEntries;
        }

        @Override
        public void checkAndAdd(String nonce) {
            long now = System.nanoTime();
            Long existing = seen.get(nonce);
            if (existing != null && existing > now) {
                throw new NonceReuseException(nonce);
            }
            seen.put(nonce, now + ttlNanos);
            if (inserts.incrementAndGet() % SWEEP_INTERVAL == 0) {
                sweep(now);
            } else if (seen.size() > maxEntries) {
                sweep(now);
            }
        }

        private void sweep(long now) {
            seen.entrySet().removeIf(e -> e.getValue() <= now);
        }
    }

    public static Store newMemNonceStore() {
        return new MemNonceStore();
    }
}