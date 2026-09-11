package dev.camada.events;

import dev.camada.Guarded;
import dev.camada.HttpTransport;
import dev.camada.Json;
import dev.camada.Transport;
import dev.camada.Transport.Request;
import dev.camada.Transport.Response;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

/**
 * EventQueue: fire-and-forget batched shipping to POST /e (ported from {@code @camada/core}
 * src/events/queue.ts). The collector ships one event per request; an in-process SDK batches,
 * flushes on size or interval, and drains at exit — but the same law holds: NOTHING here may ever
 * throw into the customer's request path, and a dead ingest must cost nothing but dropped
 * telemetry. Defaults (15 s / 500): every flush is one request and one R2 put at the analyst, so
 * the bill scales with instance count x flush cadence — not with traffic.
 *
 * <p>An ArrayDeque under the queue's own monitor, one daemon flush thread (camada-events) started
 * lazily on the first push and parked on wait(flush)/notify, single-in-flight POSTs, ≤ 1000 events
 * per POST, drop-oldest at the cap. The exit drain is a JVM shutdown hook, which runs on SIGTERM as
 * well as on a normal exit — an upgrade over the reference's atexit.
 */
public final class Queue {
  private final String url; // ingest base, e.g. https://analyst.example.com
  private final String token; // ingest token (x-tenant header)
  private volatile int maxBatch =
      500; // flush when the queue reaches this many (server caps at 1000)
  private volatile int maxQueue = 2000; // drop-oldest beyond this
  private volatile long flushMs = 15_000;
  private volatile long timeoutMs = 2000;
  private volatile Transport transport = new HttpTransport();
  private volatile String
      sdk; // '<package>/<version>': sent as x-camada-sdk on every batch (SDK-03)
  private final AtomicInteger dropped = new AtomicInteger(); // debug counter, not an API promise

  private final ArrayDeque<Object> q = new ArrayDeque<>();
  private final Object lock = new Object(); // guards q and the thread handle
  private final ReentrantLock inflight = new ReentrantLock();
  private final Object wake = new Object();
  private boolean woken; // under wake
  private volatile boolean stopped;
  private Thread thread; // under lock
  private Thread exitHook; // under lock

  public Queue(String url, String token) {
    this.url = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    this.token = token;
  }

  public Queue maxBatch(int n) {
    this.maxBatch = n;
    return this;
  }

  public Queue maxQueue(int n) {
    this.maxQueue = n;
    return this;
  }

  public Queue flushS(double seconds) {
    this.flushMs = Math.max(1, (long) (seconds * 1000));
    return this;
  }

  public Queue timeoutMs(long ms) {
    this.timeoutMs = ms;
    return this;
  }

  public Queue transport(Transport transport) {
    this.transport = transport;
    return this;
  }

  public Queue sdk(String sdk) {
    this.sdk = sdk;
    return this;
  }

  public int size() {
    synchronized (lock) {
      return q.size();
    }
  }

  public int dropped() {
    return dropped.get();
  }

  /** Whether a POST is in flight right now (what the drain queues behind). */
  boolean inFlight() {
    return inflight.isLocked();
  }

  boolean exitHookInstalled() {
    synchronized (lock) {
      return exitHook != null;
    }
  }

  /**
   * Synchronous, never throws. Starts the flush thread lazily on first push; a stopped queue stays
   * stopped (configure() replaces the engine rather than reviving one).
   */
  public void push(Object event) {
    try {
      int n;
      synchronized (lock) {
        if (q.size() >= maxQueue) {
          q.pollFirst();
          dropped.incrementAndGet();
        }
        q.addLast(event);
        n = q.size();
        if (thread == null && !stopped) {
          thread = new Thread(this::run, "camada-events");
          thread.setDaemon(true);
          thread.start();
        }
      }
      if (n >= maxBatch) {
        synchronized (wake) {
          woken = true;
          wake.notifyAll();
        }
      }
    } catch (RuntimeException err) { // never into the request path
      Guarded.logRateLimited(err);
    }
  }

  private void run() {
    while (!stopped) {
      synchronized (wake) {
        if (!woken) {
          try {
            wake.wait(flushMs);
          } catch (InterruptedException e) {
            return;
          }
        }
        woken = false;
      }
      if (stopped) {
        return;
      }
      flush();
    }
  }

  public void flush() {
    flush(false);
  }

  /**
   * Drains the queue, ≤ 1000 events per POST (the server slices there); single-in-flight; never
   * throws. {@code wait} queues behind a flush already in flight instead of yielding to it — the
   * exit drain needs the full queue gone, not just the batch someone else is posting.
   */
  public void flush(boolean wait) {
    if (wait) {
      inflight.lock();
    } else if (!inflight.tryLock()) {
      return;
    }
    try {
      Map<String, String> headers = new HashMap<>();
      headers.put("x-tenant", token);
      headers.put("content-type", "application/json");
      if (sdk != null) {
        headers.put("x-camada-sdk", sdk);
      }
      while (true) {
        List<Object> batch = new ArrayList<>();
        synchronized (lock) {
          if (q.isEmpty()) {
            return;
          }
          for (int i = 0; i < 1000 && !q.isEmpty(); i++) {
            batch.add(q.pollFirst());
          }
        }
        try {
          byte[] body = Json.stringify(batch).getBytes(StandardCharsets.UTF_8);
          Response res = transport.send(new Request("POST", url + "/e", headers, body, timeoutMs));
          if (res == null || res.status() == 0) {
            throw new IllegalStateException("ingest unreachable");
          }
        } catch (RuntimeException err) {
          dropped.addAndGet(batch.size());
          // Dropping telemetry is by design, doing it silently is not: a mount that can never
          // reach ingest looks identical to a healthy one otherwise.
          Guarded.logRateLimited(err);
        }
      }
    } finally {
      inflight.unlock();
    }
  }

  public void stop() {
    stopped = true;
    synchronized (wake) {
      woken = true;
      wake.notifyAll();
    }
    Thread hook;
    synchronized (lock) {
      thread = null;
      hook = exitHook;
      exitHook = null;
    }
    if (hook != null) {
      try {
        Runtime.getRuntime().removeShutdownHook(hook);
      } catch (IllegalStateException e) {
        // the JVM is already shutting down: the hook runs (or ran) anyway
      }
    }
  }

  /**
   * Opt-in: drain at JVM exit within a small budget, through a shutdown hook — so it runs on
   * SIGTERM and System.exit alike (an upgrade over the reference's atexit, which a bare SIGTERM
   * skips). No signal handlers of its own — an app owns its own shutdown.
   */
  public void installExitFlush() {
    installExitFlush(500);
  }

  public void installExitFlush(long budgetMs) {
    synchronized (lock) {
      if (exitHook != null) {
        return;
      }
      exitHook = new Thread(() -> drain(budgetMs), "camada-exit-flush");
      try {
        Runtime.getRuntime().addShutdownHook(exitHook);
      } catch (IllegalStateException | SecurityException e) {
        exitHook = null; // shutting down already, or not allowed: no exit drain
      }
    }
  }

  /**
   * A full drain (behind any flush in flight) on a daemon thread, abandoned once the budget is
   * spent.
   */
  public void drain(long budgetMs) {
    Thread t = new Thread(() -> flush(true), "camada-drain");
    t.setDaemon(true);
    t.start();
    try {
      t.join(Math.max(1, budgetMs));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
