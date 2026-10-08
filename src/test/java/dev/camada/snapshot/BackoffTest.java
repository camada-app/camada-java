package dev.camada.snapshot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.FakeAnalyst;
import dev.camada.Fixtures;
import dev.camada.Json;
import dev.camada.Transport.Response;
import dev.camada.snapshot.Matcher.MatchInput;
import java.util.List;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * Snapshot poll pacing (camada-all-pbv9, contract v2), driven by camada-core's
 * test/fixtures/poll/backoff.json: nextPollDelay's table, then client timelines on an injected
 * monotonic clock.
 */
class BackoffTest {
  static final Map<String, Object> FX = Fixtures.readMeta("poll/backoff.json");

  @SuppressWarnings("unchecked")
  static List<Map<String, Object>> list(Object v) {
    return (List<Map<String, Object>>) (List<?>) v;
  }

  static double num(Object v) {
    return ((Number) v).doubleValue();
  }

  @Test
  void delayTable() {
    for (Map<String, Object> c : list(FX.get("delay"))) {
      OptionalDouble got =
          Client.nextPollDelay(
              (int) num(c.get("status")),
              (String) c.get("retryAfter"),
              num(c.get("refreshSeconds")));
      Object want = c.get("expectDelaySeconds");
      String name = (String) c.get("name");
      if (want == null) {
        assertFalse(got.isPresent(), name);
      } else {
        assertTrue(got.isPresent(), name);
        assertEquals(num(want), got.getAsDouble(), 1e-9, name);
      }
    }
  }

  @Test
  void timelines() {
    String blocked = (String) FX.get("blockedIp");
    for (Map<String, Object> tl : list(FX.get("timelines"))) {
      FakeAnalyst a = new FakeAnalyst();
      AtomicLong clock = new AtomicLong();
      double base = num(tl.get("clockBase"));
      Client c =
          new Client(ClientTest.URL, "snap-test")
              .transport(
                  req -> {
                    Response r = a.send(req);
                    return r;
                  })
              .refreshS(num(tl.get("refreshSeconds")))
              .mode(Client.Mode.LAZY);
      c.nanos = clock::get;
      for (Map<String, Object> st : list(tl.get("steps"))) {
        String where = tl.get("name") + " @t=" + st.get("t");
        clock.set((long) ((base + num(st.get("t"))) * 1e9));
        assertEquals(st.get("poll"), c.due(), where);
        if (!Boolean.TRUE.equals(st.get("poll"))) {
          continue;
        }
        Map<String, Object> resp = Json.asMap(st.get("respond"));
        int status = (int) num(resp.get("status"));
        String ra = (String) resp.get("retryAfter");
        c.transport(
            req ->
                status == 200
                    ? a.send(req)
                    : new Response(
                        status, ra == null ? Map.of() : Map.of("retry-after", ra), new byte[0]));
        c.refresh();
        Map<String, Object> after = Json.asMap(st.get("after"));
        var v = c.verdict(MatchInput.ip(blocked));
        assertEquals(after.get("cold"), "cold".equals(v.reason()), where + " cold");
        assertEquals(after.get("blocked"), v.block(), where + " blocked");
      }
    }
  }

  private static final class Counting {
    final AtomicInteger snapshotRequests = new AtomicInteger();
    volatile boolean fail;
    final FakeAnalyst analyst = new FakeAnalyst();

    Response send(dev.camada.Transport.Request req) {
      if (!fail) {
        return analyst.send(req);
      }
      snapshotRequests.incrementAndGet();
      return new Response(503, Map.of("retry-after", "30"), new byte[0]);
    }
  }

  private static void quiesce() throws InterruptedException {
    Thread.sleep(200); // the single executor thread drains what the request path queued
  }

  /** Request path under a closed gate: warm, stale, 503 retry-after 30 -> one request per 30 s. */
  @Test
  void requestPathAndTickHonourTheGate() throws Exception {
    Counting t = new Counting();
    AtomicLong clock = new AtomicLong(1_000_000_000_000L);
    Client c =
        new Client(ClientTest.URL, "snap-test")
            .transport(t::send)
            .refreshS(30)
            .mode(Client.Mode.LAZY);
    c.nanos = clock::get;
    c.refresh(); // warm with a 200
    clock.addAndGet(28_000_000_000L); // stale, gate open
    t.fail = true;
    c.ensureFresh();
    long deadline = System.nanoTime() + 5_000_000_000L;
    while (c.due() && System.nanoTime() < deadline) {
      Thread.sleep(5);
    }
    assertEquals(1, t.snapshotRequests.get());
    for (int i = 0; i < 20; i++) {
      c.ensureFresh();
    }
    c.refreshIfDue(); // the timer tick
    quiesce();
    assertEquals(1, t.snapshotRequests.get(), "gated: stale but not due");
    clock.addAndGet(30_000_000_000L);
    c.ensureFresh();
    deadline = System.nanoTime() + 5_000_000_000L;
    while (t.snapshotRequests.get() < 2 && System.nanoTime() < deadline) {
      Thread.sleep(5);
    }
    quiesce();
    assertEquals(2, t.snapshotRequests.get(), "gate elapsed: one more poll");
  }

  /** A transport that throws is a poll nobody answered (gated as status 0) and is still logged. */
  @Test
  void throwingTransportIsLoggedAndGated() throws Exception {
    java.util.logging.Logger log = java.util.logging.Logger.getLogger("camada");
    java.util.List<String> lines = new java.util.concurrent.CopyOnWriteArrayList<>();
    java.util.logging.Handler h =
        new java.util.logging.Handler() {
          @Override
          public void publish(java.util.logging.LogRecord r) {
            lines.add(r.getMessage());
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    java.lang.reflect.Field f = dev.camada.Guarded.class.getDeclaredField("lastLogNanos");
    f.setAccessible(true);
    f.setLong(null, Long.MIN_VALUE); // forget any line already logged this minute
    log.addHandler(h);
    try {
      AtomicLong clock = new AtomicLong(1_000_000_000_000L);
      Client c =
          new Client(ClientTest.URL, "snap-test")
              .transport(
                  req -> {
                    throw new IllegalStateException("boom");
                  })
              .refreshS(30)
              .mode(Client.Mode.LAZY);
      c.nanos = clock::get;
      c.refresh();
      assertTrue(lines.stream().anyMatch(l -> l.contains("boom")), lines.toString());
      assertFalse(c.due(), "gated as status 0");
      clock.addAndGet(5_000_000_000L);
      assertTrue(c.due(), "5 s floor elapsed");
    } finally {
      log.removeHandler(h);
    }
  }
}
