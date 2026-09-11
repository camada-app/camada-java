package dev.camada.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.FakeAnalyst;
import dev.camada.Transport;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * EventQueue: fire-and-forget batched shipping to POST /e. Nothing here may ever raise into the
 * customer's request path, and a dead ingest must cost nothing but dropped telemetry.
 */
class QueueTest {
  static Queue queue(FakeAnalyst a) {
    return new Queue("https://analyst.test", "tok-test").transport(a).sdk("@camada/java/0.0.0");
  }

  static Map<String, Object> ev(String k, Object v) {
    Map<String, Object> m = new java.util.LinkedHashMap<>();
    m.put(k, v);
    return m;
  }

  static void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  static void awaitEvents(FakeAnalyst a) {
    for (int k = 0; k < 200 && a.events.isEmpty(); k++) {
      sleep(5);
    }
  }

  @Test
  void flushPostsAJsonArrayWithTheTenantAndSdkHeaders() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a);
    q.push(ev("p", "/"));
    q.flush();
    assertEquals(List.of(List.of(ev("p", "/"))), a.events);
    assertEquals(List.of("@camada/java/0.0.0"), a.sdkHeaders);
    q.stop();
  }

  @Test
  void postsToIngestSlashEWithTheContractHeaders() {
    List<Transport.Request> seen = new ArrayList<>();
    Queue q =
        new Queue("https://analyst.test/", "tok-test")
            .sdk("@camada/java/0.0.0")
            .transport(
                req -> {
                  seen.add(req);
                  return new Transport.Response(202, Map.of(), new byte[0]);
                });
    q.push(ev("i", 1L));
    q.flush();
    Transport.Request r = seen.get(0);
    assertEquals("POST", r.method());
    assertEquals(
        "https://analyst.test/e", r.url()); // one trailing slash on the base is not two in the path
    assertEquals("tok-test", r.headers().get("x-tenant"));
    assertEquals("application/json", r.headers().get("content-type"));
    assertEquals("[{\"i\":1}]", new String(r.body()));
    assertEquals(2000, r.timeoutMs());
    q.stop();
  }

  @Test
  void flushesWhenTheBatchSizeIsReached() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a).maxBatch(3).flushS(60);
    for (int i = 0; i < 3; i++) {
      q.push(ev("i", (long) i));
    }
    awaitEvents(a);
    assertEquals(List.of(List.of(ev("i", 0L), ev("i", 1L), ev("i", 2L))), a.events);
    q.stop();
  }

  @Test
  void flushesOnTheInterval() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a).flushS(0.02);
    q.push(ev("i", 1L));
    awaitEvents(a);
    assertEquals(List.of(List.of(ev("i", 1L))), a.events);
    q.stop();
  }

  @Test
  void drainsInSlicesOf1000() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a).maxBatch(5000).maxQueue(5000);
    for (int i = 0; i < 1500; i++) {
      q.push(ev("i", (long) i));
    }
    q.flush();
    assertEquals(List.of(1000, 500), a.events.stream().map(List::size).toList());
    q.stop();
  }

  @Test
  void dropsOldestBeyondTheQueueCap() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a).maxQueue(3).maxBatch(100).flushS(60);
    for (int i = 0; i < 5; i++) {
      q.push(ev("i", (long) i));
    }
    assertEquals(3, q.size());
    assertEquals(2, q.dropped());
    q.flush();
    assertEquals(List.of(List.of(ev("i", 2L), ev("i", 3L), ev("i", 4L))), a.events);
    q.stop();
  }

  @Test
  void deadIngestDropsSilentlyAndRecovers() {
    FakeAnalyst a = new FakeAnalyst();
    a.ingestDown = true;
    Queue q = queue(a);
    q.push(ev("i", 1L));
    q.flush();
    assertEquals(1, q.dropped());
    assertEquals(0, q.size());
    a.ingestDown = false;
    q.push(ev("i", 2L));
    q.flush();
    assertEquals(List.of(List.of(ev("i", 2L))), a.events);
    q.stop();
  }

  @Test
  void pushAndFlushNeverRaise() {
    Queue q =
        new Queue("https://analyst.test", "tok-test")
            .transport(
                req -> {
                  throw new IllegalStateException("broken transport");
                });
    q.push(ev("i", 1L));
    q.push(new Object()); // not even serialisable: dropped at flush, never thrown
    q.flush(); // a broken transport is swallowed and logged, never raised
    assertEquals(0, q.size());
    assertEquals(2, q.dropped());
    q.stop();
  }

  @Test
  void stopEndsTheFlushThread() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a).flushS(0.01);
    q.push(ev("i", 1L));
    q.stop();
    sleep(30);
    int n = a.events.size();
    q.push(ev("i", 2L));
    sleep(30);
    assertEquals(n, a.events.size()); // nothing flushes on its own after stop()
  }

  @Test
  void flushThreadIsADaemonNamedCamadaEvents() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a).flushS(60);
    q.push(ev("i", 1L));
    Thread found = null;
    for (Thread t : Thread.getAllStackTraces().keySet()) {
      if (t.getName().equals("camada-events") && t.isAlive()) {
        found = t;
      }
    }
    assertTrue(found != null && found.isDaemon());
    q.stop();
  }

  @Test
  void aWaitingFlushDrainsBehindTheOneInFlight() throws InterruptedException {
    FakeAnalyst a = new FakeAnalyst();
    CountDownLatch gate = new CountDownLatch(1);
    Queue q = queue(a).maxBatch(1).flushS(60);
    q.transport(
        req -> {
          try {
            gate.await(
                2, TimeUnit.SECONDS); // the periodic flush is mid-POST when the exit drain starts
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          return a.send(req);
        });
    q.push(ev("i", 1L));
    for (int k = 0; k < 100 && !q.inFlight(); k++) {
      sleep(5);
    }
    assertTrue(q.inFlight());
    q.push(ev("i", 2L));
    q.flush(); // the request-path flush yields to the one in flight
    assertEquals(List.of(), a.events);
    Thread t = new Thread(() -> q.drain(2000));
    t.start();
    gate.countDown();
    t.join(2000);
    assertEquals(List.of(List.of(ev("i", 1L)), List.of(ev("i", 2L))), a.events);
    q.stop();
  }

  @Test
  void drainGivesUpAfterItsBudget() {
    FakeAnalyst a = new FakeAnalyst();
    CountDownLatch gate = new CountDownLatch(1);
    Queue q = queue(a).flushS(60);
    q.transport(
        req -> {
          try {
            gate.await(5, TimeUnit.SECONDS);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
          return a.send(req);
        });
    q.push(ev("i", 1L));
    long t0 = System.nanoTime();
    q.drain(50); // a stuck ingest must not hold the JVM's exit hostage
    long tookMs = (System.nanoTime() - t0) / 1_000_000;
    assertTrue(tookMs < 1500, "drain took " + tookMs + " ms");
    gate.countDown();
    q.stop();
  }

  @Test
  void installExitFlushRegistersOneShutdownHookAndStopRemovesIt() {
    FakeAnalyst a = new FakeAnalyst();
    Queue q = queue(a);
    q.installExitFlush();
    q.installExitFlush();
    assertTrue(q.exitHookInstalled());
    q.stop();
    assertTrue(!q.exitHookInstalled());
  }
}
