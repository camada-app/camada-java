package dev.camada;

import java.util.logging.Logger;

/**
 * The fail-open envelope: a camada bug must never 5xx the customer. Every public entry point of the
 * SDK catches, falls back, and reports through {@link #logRateLimited}: at most one line a minute,
 * on java.util.logging's "camada" logger (bridged wherever the host bridges JUL). The line carries
 * the error's toString only — never a stack trace — so a log scraper sees one message, not a
 * traceback.
 */
public final class Guarded {
  private Guarded() {}

  private static final Logger LOG = Logger.getLogger("camada");
  private static volatile long lastLogNanos = Long.MIN_VALUE;
  private static final long MINUTE_NANOS = 60_000_000_000L;

  public static void logRateLimited(Object err) {
    long now = System.nanoTime();
    long last = lastLogNanos;
    if (last != Long.MIN_VALUE && now - last < MINUTE_NANOS) {
      return;
    }
    lastLogNanos = now;
    try {
      LOG.severe("[camada] suppressed error (SDK fails open): " + err);
    } catch (RuntimeException ignored) {
      // even logging must not raise
    }
  }
}
