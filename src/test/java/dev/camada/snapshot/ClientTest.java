package dev.camada.snapshot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import dev.camada.FakeAnalyst;
import dev.camada.HttpTransport;
import dev.camada.Transport;
import dev.camada.Transport.Request;
import dev.camada.Transport.Response;
import dev.camada.snapshot.Matcher.MatchInput;
import dev.camada.snapshot.Matcher.MatchResult;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle over the GET
 * /snapshot contract (200 frame + etag + x-camada-config; 304 unchanged; 204 nothing published ->
 * enforce nothing). Cold = fail open; any error keeps the previous snapshot.
 */
class ClientTest {
  static final String URL = "https://analyst.test/snapshot";

  static Client client(FakeAnalyst a) {
    return new Client(URL, "snap-test")
        .transport(a)
        .sdk("@camada/java/0.0.0")
        .mode(Client.Mode.LAZY);
  }

  static void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  static void awaitLoaded(Client c) {
    for (int k = 0; k < 400 && "cold".equals(c.verdict(MatchInput.ip("0.0.0.0")).reason()); k++) {
      sleep(5);
    }
  }

  @Test
  void coldClientFailsOpen() {
    Client c = client(new FakeAnalyst());
    MatchResult v = c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP));
    assertEquals("cold", v.reason());
    assertFalse(v.block() || v.challenge() || v.allowed());
  }

  @Test
  void loadsAndEnforcesWithTheContractHeaders() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.refresh();
    assertTrue(c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP)).block());
    Request req = a.snapshotRequests.get(0);
    assertEquals("Bearer snap-test", req.headers().get("authorization"));
    assertEquals("@camada/java/0.0.0", req.headers().get("x-camada-sdk"));
    assertEquals("5", req.headers().get("x-camada-snapshot"));
    assertEquals("gzip", req.headers().get("accept-encoding"));
    assertFalse(req.headers().containsKey("if-none-match"));
    assertEquals("acme", c.config().tenant());
    assertEquals(Boolean.TRUE, c.config().beacon());
    assertEquals("none", c.config().trustedProxy().mode());
  }

  @Test
  void a304RepeatsConfigAndKeepsTheSnapshot() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.refresh();
    a.config.put("beacon", false);
    c.refresh();
    assertEquals(a.etag(), a.snapshotRequests.get(1).headers().get("if-none-match"));
    assertTrue(c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP)).block());
    assertEquals(Boolean.FALSE, c.config().beacon());
  }

  @Test
  void a204MeansNothingPublishedAndNotCold() {
    FakeAnalyst a = new FakeAnalyst();
    a.snapshotStatus = 204;
    Client c = client(a);
    c.refresh();
    MatchResult v = c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP));
    assertNull(v.reason());
    assertFalse(v.block());
  }

  @Test
  void errorsKeepWhatWeHave() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.refresh();
    for (int status : new int[] {401, 500}) {
      a.snapshotStatus = status;
      c.refresh();
      assertTrue(c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP)).block());
    }
    a.snapshotStatus = null;
    a.snapshotDown = true;
    c.refresh();
    assertTrue(c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP)).block());
  }

  @Test
  void corruptBodyKeepsThePreviousSnapshot() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.refresh();
    Transport corrupt =
        req -> {
          Response r = a.send(req);
          Map<String, String> h = new HashMap<>(r.headers());
          h.put("etag", "\"other\"");
          byte[] junk = new byte[15];
          junk[0] = 5;
          System.arraycopy("junk!".getBytes(), 0, junk, 4, 5);
          return new Response(200, h, junk);
        };
    c.transport(corrupt);
    c.refresh();
    assertTrue(c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP)).block());
    // a frame shorter than its own meta length, and one shorter than the length word
    c.transport(req -> new Response(200, Map.of("etag", "\"x\""), new byte[] {9, 0, 0, 0, 1}));
    c.refresh();
    c.transport(req -> new Response(200, Map.of("etag", "\"y\""), new byte[] {1}));
    c.refresh();
    assertTrue(c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP)).block());
  }

  @Test
  void sameVersionNewEtagReparses() {
    // the server ships v3/v4/v5 bodies of one publish under the same meta.version and different
    // etags
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.refresh();
    assertFalse(c.verdict(MatchInput.ip("192.0.2.20")).challenge()); // v3 has no challenge side
    a.container = "v4";
    c.refresh();
    assertTrue(c.verdict(MatchInput.ip("192.0.2.20")).challenge());
  }

  @Test
  void sameVersionSameEtagIsNotReparsed() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.refresh();
    Matcher first = c.matcher();
    a.snapshotStatus = null;
    // force a 200 with the same etag: the client keeps the matcher it has
    Transport again =
        req -> a.send(new Request(req.method(), req.url(), Map.of(), null, req.timeoutMs()));
    c.transport(again);
    c.refresh();
    assertSame(first, c.matcher());
  }

  @Test
  void snapshotVersionHeaderFollowsTheOption() {
    FakeAnalyst a = new FakeAnalyst();
    client(a).snapshotVersion(4).refresh();
    client(a).snapshotVersion(3).refresh();
    assertEquals(List.of("4", ""), a.snapshotVersions);
  }

  @Test
  void serverSteersTheCadenceUnlessPinned() {
    FakeAnalyst a = new FakeAnalyst();
    a.config.put("poll_seconds", 7L);
    Client c = client(a);
    c.refresh();
    assertEquals(7.0, c.refreshS());
    a.config.put("poll_seconds", 1L); // below the 5 s floor: ignored
    c.refresh();
    assertEquals(7.0, c.refreshS());
    Client pinned = client(a).refreshS(11.0);
    pinned.refresh();
    assertEquals(11.0, pinned.refreshS());
  }

  @Test
  void ensureFreshIsOffPathAndSingleInFlight() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.ensureFresh();
    c.ensureFresh();
    awaitLoaded(c);
    assertTrue(c.verdict(MatchInput.ip(FakeAnalyst.BLOCKED_IP)).block());
    assertEquals(1, a.snapshotRequests.size());
    c.ensureFresh(); // fresh: no new poll
    sleep(20);
    assertEquals(1, a.snapshotRequests.size());
    c.stop();
  }

  @Test
  void timerModePollsOnItsOwnAndStops() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = new Client(URL, "snap-test").transport(a).mode(Client.Mode.TIMER).refreshS(0.02);
    c.start();
    try {
      for (int k = 0; k < 200 && a.snapshotRequests.size() < 3; k++) {
        sleep(5);
      }
      assertTrue(a.snapshotRequests.size() >= 3);
    } finally {
      c.stop();
    }
    int n = a.snapshotRequests.size();
    sleep(50);
    assertEquals(n, a.snapshotRequests.size());
    c.ensureFresh(); // a stopped client never polls again
    sleep(20);
    assertEquals(n, a.snapshotRequests.size());
  }

  @Test
  void timerThreadIsADaemonNamedCamadaSnapshot() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = new Client(URL, "snap-test").transport(a).mode(Client.Mode.TIMER).refreshS(0.02);
    c.start();
    try {
      awaitLoaded(c);
      Thread found = null;
      for (Thread t : Thread.getAllStackTraces().keySet()) {
        if (t.getName().equals("camada-snapshot")) {
          found = t;
        }
      }
      assertNotNull(found);
      assertTrue(found.isDaemon());
    } finally {
      c.stop();
    }
  }

  @Test
  void httpTransportGunzipsAndNeverRaises() throws Exception {
    byte[] payload = FakeAnalyst.frame(Map.of("version", "z"), "BLK".getBytes());
    HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    srv.createContext(
        "/snapshot",
        ex -> {
          byte[] body = FakeAnalyst.gzipBytes(payload);
          ex.getResponseHeaders().add("content-encoding", "gzip");
          ex.getResponseHeaders().add("etag", "\"z\"");
          ex.sendResponseHeaders(200, body.length);
          try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
          }
        });
    srv.createContext(
        "/e",
        ex -> {
          ex.sendResponseHeaders(401, -1);
          ex.close();
        });
    srv.start();
    Transport t = new HttpTransport();
    try {
      int port = srv.getAddress().getPort();
      Response r =
          t.send(
              new Request(
                  "GET",
                  "http://127.0.0.1:" + port + "/snapshot",
                  Map.of("accept-encoding", "gzip"),
                  null,
                  2000));
      assertEquals(200, r.status());
      assertArrayEquals(payload, r.body());
      assertEquals("\"z\"", r.headers().get("etag"));
      assertFalse(r.headers().containsKey("content-encoding"));
      Response e =
          t.send(
              new Request(
                  "POST",
                  "http://127.0.0.1:" + port + "/e",
                  Map.of("x-tenant", "t"),
                  "[]".getBytes(),
                  2000));
      assertEquals(401, e.status()); // an HTTP error is an answer, not an exception
    } finally {
      srv.stop(0);
    }
    Response dead = t.send(new Request("GET", "http://127.0.0.1:1/snapshot", Map.of(), null, 200));
    assertEquals(0, dead.status());
    Response bad = t.send(new Request("GET", "not a url", Map.of(), null, 200));
    assertEquals(0, bad.status());
  }

  @Test
  void nonFinitePollSecondsIsIgnored() {
    FakeAnalyst a = new FakeAnalyst();
    a.config.put(
        "poll_seconds",
        Double.POSITIVE_INFINITY); // json spells it 1e999; a wait(inf) would kill the timer
    Client c = client(a);
    double before = c.refreshS();
    c.refresh();
    assertEquals(before, c.refreshS());
    a.config.put("poll_seconds", Double.NaN);
    c.refresh();
    assertEquals(before, c.refreshS());
    a.config.put("poll_seconds", "soon");
    c.refresh();
    assertEquals(before, c.refreshS());
    assertNotEquals(0.0, before);
  }

  @Test
  void aJunkConfigHeaderKeepsThePreviousConfig() {
    FakeAnalyst a = new FakeAnalyst();
    Client c = client(a);
    c.refresh();
    Transport junk =
        req -> {
          Response r = a.send(req);
          Map<String, String> h = new HashMap<>(r.headers());
          h.put("x-camada-config", "{not json");
          return new Response(r.status(), h, r.body());
        };
    c.transport(junk);
    c.refresh();
    assertEquals("acme", c.config().tenant());
    c.transport(
        req -> {
          Response r = a.send(req);
          Map<String, String> h = new HashMap<>(r.headers());
          h.put("x-camada-config", "[1,2]");
          return new Response(r.status(), h, r.body());
        });
    c.refresh();
    assertEquals("acme", c.config().tenant());
  }
}
