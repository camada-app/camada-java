package dev.camada;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
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

  private static final Set<String> LOGGED_ONCE = ConcurrentHashMap.newKeySet();
  private static final int LOGGED_ONCE_MAX = 1000;

  /**
   * Logs {@code msg} at WARNING the first time {@code key} is seen in this process. Apart from
   * {@link #logRateLimited}'s budget, so a dropped regex cannot hide a real error. The key set is
   * capped (about 1000), past which nothing more is logged; pass a short key, the set keeps it.
   */
  public static void logOnce(String key, String msg) {
    try {
      if (LOGGED_ONCE.size() < LOGGED_ONCE_MAX && LOGGED_ONCE.add(key)) {
        LOG.warning(msg);
      }
    } catch (RuntimeException ignored) {
      // even logging must not raise
    }
  }
}
