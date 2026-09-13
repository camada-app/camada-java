package dev.camada.servlet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.Camada;
import dev.camada.Context;
import dev.camada.FakeAnalyst;
import dev.camada.Hosts;
import dev.camada.Hosts.Call;
import dev.camada.Hosts.Reply;
import dev.camada.Hosts.ServletDriver;
import dev.camada.Options;
import dev.camada.Passed;
import dev.camada.Req;
import dev.camada.Result;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockAsyncContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * What only the servlet host can show: the request mapping, a body camada read being replayed to
 * the app, async completion, sendError, the dispatcher-type guard, the static helpers, and the
 * lazily wired default engine.
 */
class FilterTest {
  FakeAnalyst analyst;
  Camada engine;

  @BeforeEach
  void up() {
    analyst = new FakeAnalyst();
    engine = Hosts.engineWith(analyst);
    Hosts.loaded(engine);
  }

  @AfterEach
  void down() {
    engine.stop();
    Camada.resetDefault();
  }

  List<Map<String, Object>> events() {
    engine.queue().flush();
    return analyst.allEvents();
  }

  @Test
  void requestMapping() {
    MockHttpServletRequest r =
        ServletDriver.request(
            new Call("PUT", "/a?x=1")
                .header("Host", "h")
                .header("X-Forwarded-For", "5.6.7.8")
                .header("Cookie", "a=1")
                .header("Cookie", "_sfp=abc")
                .header("Accept", "text/html")
                .header("Accept", "*/*")
                .header("Content-Type", "text/plain")
                .https(true)
                .peer("::ffff:1.2.3.4")
                .body("abc"));
    Req req = CamadaFilter.reqFrom(r);
    assertEquals("PUT", req.method());
    assertEquals("/a", req.path());
    assertEquals("?x=1", req.query());
    assertEquals("h", req.host());
    assertEquals("1.1", req.httpVersion());
    assertEquals("::ffff:1.2.3.4", req.peer());
    assertTrue(req.https());
    assertEquals("5.6.7.8", req.header("x-forwarded-for"));
    assertEquals("text/plain", req.header("content-type"));
    // HTTP/2 clients send one cookie per field; the join is '; ' for cookies and ', ' otherwise
    assertEquals("a=1; _sfp=abc", req.header("cookie"));
    assertEquals("text/html, */*", req.header("accept"));
    assertNull(req.header("x-none"));
    for (Map.Entry<String, String> h : req.headers()) {
      assertEquals(h.getKey().toLowerCase(), h.getKey()); // names lower-cased, order kept
    }
    MockHttpServletRequest bare = new MockHttpServletRequest();
    bare.setRequestURI(null);
    bare.setProtocol("HTTP/2.0");
    Req b = CamadaFilter.reqFrom(bare);
    assertEquals("/", b.path());
    assertEquals("", b.query());
    assertEquals("2.0", b.httpVersion());
    assertEquals("localhost", b.host()); // no host header: the server name
  }

  @Test
  void cookiesSplitOverSeveralFieldsStillJoinTheSession() throws Exception {
    ServletDriver d = new ServletDriver(engine);
    d.call(new Call("GET", "/").header("cookie", "a=1").header("cookie", "_sfp=abc"));
    d.call(new Call("GET", "/").header("cookie", "a=1").header("cookie", "_sfp=abc"));
    List<Map<String, Object>> evs = events();
    assertEquals(2, evs.size());
    for (Map<String, Object> e : evs) {
      assertEquals("abc", e.get("sid"));
      assertEquals(0L, ((Number) e.get("ns")).longValue());
    }
  }

  @Test
  void aBodyCamadaReadIsReplayedToTheApp() throws Exception {
    analyst.config.put("beacon", false);
    engine.snapshot().refresh();
    byte[][] got = new byte[1][];
    ServletDriver d =
        new ServletDriver(
            engine,
            req -> {
              got[0] = req.getInputStream().readAllBytes();
              return Reply.of(200, "ok".getBytes());
            });
    // a beacon POST with the beacon off falls through unread: the app reads the body itself
    Reply r = d.call(new Call("POST", "/_cam/fp").body("{}"));
    assertEquals("ok", r.text());
    assertArrayEquals("{}".getBytes(), got[0]);
    assertFalse(d.seen.get(0) instanceof ReplayRequestWrapper);
    // a verify POST camada read but could not answer (no ip) is replayed: head, then the rest
    Reply r2 = d.call(new Call("POST", "/__camada/challenge").body("nonce=x&to=%2F").peer(null));
    assertEquals("ok", r2.text());
    assertArrayEquals("nonce=x&to=%2F".getBytes(), got[0]);
    assertTrue(d.seen.get(1) instanceof ReplayRequestWrapper);
  }

  @Test
  void aBodyOverTheCapReachesTheAppWhole() throws Exception {
    // no ip -> camada never answers the verify endpoint, so the app gets the request with its full
    // body
    byte[] big = new byte[70_000];
    java.util.Arrays.fill(big, (byte) 'x');
    byte[][] got = new byte[1][];
    String[] viaReader = new String[1];
    ServletDriver d =
        new ServletDriver(
            engine,
            req -> {
              got[0] = req.getInputStream().readAllBytes();
              return Reply.of(200, "ok".getBytes());
            });
    Reply r = d.call(new Call("POST", "/__camada/challenge").body(big).peer(null));
    assertEquals("ok", r.text());
    assertArrayEquals(big, got[0]);
    // the same through getReader(), on a declared-over-cap body (nothing was read at all)
    ServletDriver d2 =
        new ServletDriver(
            engine,
            req -> {
              viaReader[0] = req.getReader().readLine();
              return Reply.of(200, "ok".getBytes());
            });
    d2.call(new Call("POST", "/__camada/challenge").body("hello").contentLength(5000).peer(null));
    assertEquals("hello", viaReader[0]);
  }

  @Test
  void ridAndCookieAreStampedBeforeTheChainRuns() throws Exception {
    ServletDriver d =
        new ServletDriver(
            engine,
            req -> {
              Context ctx = (Context) req.getAttribute("camada");
              return Reply.of(200, "seen".getBytes(), "x-app-rid", ctx.rid());
            });
    Reply r = d.call(new Call("GET", "/"));
    assertEquals(r.header("x-rid"), r.header("x-app-rid"));
    assertTrue(r.header("set-cookie").startsWith("_sfp="));
  }

  @Test
  void sendErrorStatusReachesTheEvent() throws Exception {
    ServletDriver d =
        new ServletDriver(
            engine,
            req -> {
              throw new IllegalStateException("unused");
            });
    MockHttpServletRequest req = ServletDriver.request(new Call("GET", "/missing"));
    MockHttpServletResponse res = new MockHttpServletResponse();
    FilterChain chain = (rq, rs) -> ((HttpServletResponse) rs).sendError(404, "nope");
    d.filter.doFilter(req, res, chain);
    assertEquals(404, res.getStatus());
    assertEquals(404L, ((Number) events().get(0).get("st")).longValue());
    assertNotNull(res.getHeader("x-rid"));
  }

  @Test
  void asyncCompletionFiresOnFinishOnceWithTheFinalStatus() throws Exception {
    MockHttpServletRequest req = ServletDriver.request(new Call("GET", "/async"));
    req.setAsyncSupported(true);
    MockHttpServletResponse res = new MockHttpServletResponse();
    CamadaFilter filter = new CamadaFilter(engine);
    MockAsyncContext[] ctx = new MockAsyncContext[1];
    FilterChain chain =
        (rq, rs) -> {
          ctx[0] = (MockAsyncContext) rq.startAsync(rq, rs);
        };
    filter.doFilter(req, res, chain);
    assertEquals(0, events().size()); // nothing shipped while the request is still in flight
    // startAsync() hands the app the container's own response, so the status is set past the
    // wrapper; it must still reach the event
    res.setStatus(202);
    ctx[0].complete();
    List<Map<String, Object>> evs = events();
    assertEquals(1, evs.size());
    assertEquals(202L, ((Number) evs.get(0).get("st")).longValue());
    assertEquals("/async", evs.get(0).get("p"));
    ctx[0].complete(); // a second completion never ships a second event
    assertEquals(1, events().size());
  }

  /** An engine whose Passed counts the onFinish calls it gets. */
  Camada counting(AtomicInteger finishes) {
    Camada counting =
        new Camada(new Options().env(Hosts.ENV).transport(analyst)) {
          @Override
          public Result handle(Req req, byte[] body) {
            Result r = super.handle(req, body);
            if (r instanceof Passed p && p.onFinish() != null) {
              return new Passed(
                  p.rid(),
                  p.setCookie(),
                  p.ctx(),
                  st -> {
                    finishes.incrementAndGet();
                    p.onFinish().accept(st);
                  });
            }
            return r;
          }
        };
    Hosts.loaded(counting);
    return counting;
  }

  @Test
  void onFinishFiresExactlyOnceWhenTheAppThrows() throws Exception {
    AtomicInteger finishes = new AtomicInteger();
    Camada counting = counting(finishes);
    try {
      ServletDriver d =
          new ServletDriver(
              counting,
              req -> {
                throw new ServletException("boom");
              });
      assertThrows(ServletException.class, () -> d.call(new Call("GET", "/x")));
      assertEquals(1, finishes.get());
      ServletDriver io =
          new ServletDriver(
              counting,
              req -> {
                throw new IOException("pipe");
              });
      assertThrows(IOException.class, () -> io.call(new Call("GET", "/y")));
      assertEquals(2, finishes.get());
      counting.queue().flush();
      for (Map<String, Object> e : analyst.allEvents()) {
        assertEquals(500L, ((Number) e.get("st")).longValue());
      }
    } finally {
      counting.stop();
    }
  }

  @Test
  void sendErrorThenAnExceptionStillFiresOnceWith500() throws Exception {
    AtomicInteger finishes = new AtomicInteger();
    Camada counting = counting(finishes);
    try {
      CamadaFilter filter = new CamadaFilter(counting);
      MockHttpServletRequest req = ServletDriver.request(new Call("GET", "/half"));
      MockHttpServletResponse res = new MockHttpServletResponse();
      FilterChain chain =
          (rq, rs) -> {
            ((HttpServletResponse) rs).sendError(404, "nope");
            throw new IllegalStateException("after sendError");
          };
      assertThrows(IllegalStateException.class, () -> filter.doFilter(req, res, chain));
      assertEquals(1, finishes.get());
      counting.queue().flush();
      List<Map<String, Object>> evs = analyst.allEvents();
      assertEquals(1, evs.size());
      assertEquals(500L, ((Number) evs.get(0).get("st")).longValue()); // the app threw: 500
    } finally {
      counting.stop();
    }
  }

  @Test
  void anAsyncStartThenAnExceptionFiresOnceAndCompletionShipsNothingMore() throws Exception {
    AtomicInteger finishes = new AtomicInteger();
    Camada counting = counting(finishes);
    try {
      CamadaFilter filter = new CamadaFilter(counting);
      MockHttpServletRequest req = ServletDriver.request(new Call("GET", "/async-boom"));
      req.setAsyncSupported(true);
      MockHttpServletResponse res = new MockHttpServletResponse();
      MockAsyncContext[] ctx = new MockAsyncContext[1];
      FilterChain chain =
          (rq, rs) -> {
            ctx[0] = (MockAsyncContext) rq.startAsync(rq, rs);
            throw new IllegalStateException("after startAsync");
          };
      assertThrows(IllegalStateException.class, () -> filter.doFilter(req, res, chain));
      assertEquals(1, finishes.get());
      res.setStatus(202);
      ctx[0].complete(); // the listener was never registered: nothing more ships
      assertEquals(1, finishes.get());
      counting.queue().flush();
      List<Map<String, Object>> evs = analyst.allEvents();
      assertEquals(1, evs.size());
      assertEquals(500L, ((Number) evs.get(0).get("st")).longValue());
    } finally {
      counting.stop();
    }
  }

  @Test
  void onlyTheOriginalDispatchIsHandled() throws Exception {
    MockHttpServletRequest req =
        ServletDriver.request(new Call("GET", "/").peer(FakeAnalyst.BLOCKED_IP));
    req.setDispatcherType(DispatcherType.ERROR);
    MockHttpServletResponse res = new MockHttpServletResponse();
    boolean[] ran = new boolean[1];
    new CamadaFilter(engine).doFilter(req, res, (rq, rs) -> ran[0] = true);
    assertTrue(
        ran[0]); // an ERROR / ASYNC / FORWARD dispatch passes straight through, nothing stamped
    assertNull(res.getHeader("x-rid"));
    assertEquals(0, events().size());
  }

  @Test
  void nonHttpRequestsPassThrough() throws Exception {
    boolean[] ran = new boolean[1];
    // a ServletRequestWrapper is a ServletRequest but not an HttpServletRequest
    new CamadaFilter(engine)
        .doFilter(
            new jakarta.servlet.ServletRequestWrapper(new MockHttpServletRequest()),
            new jakarta.servlet.ServletResponseWrapper(new MockHttpServletResponse()),
            (rq, rs) -> ran[0] = true);
    assertTrue(ran[0]);
  }

  @Test
  void staticHelpersReadTheRequestContext() throws Exception {
    ServletDriver d =
        new ServletDriver(
            engine,
            req -> {
              String tag = Camada.scriptTag(req);
              Camada.track(req, "signup", "bob");
              return Reply.of(200, tag.getBytes());
            });
    Reply r = d.call(new Call("GET", "/"));
    assertEquals(
        "<script src=\"/_cam/b.js?r=" + r.header("x-rid") + "\" async></script>", r.text());
    List<Map<String, Object>> evs = events();
    Map<String, Object> tracked =
        evs.stream().filter(e -> e.get("et") != null).findFirst().orElseThrow();
    assertEquals("signup", tracked.get("et"));
    assertEquals(r.header("x-rid"), tracked.get("rid"));
    assertNotNull(tracked.get("uid"));
    // without the filter and without a default engine: silent no-ops, and no engine gets built
    MockHttpServletRequest bare = new MockHttpServletRequest();
    Camada.resetDefault();
    assertEquals("", Camada.scriptTag(bare));
    Camada.track(bare, "signup", null);
    assertFalse(Camada.serveChallenge(bare, new MockHttpServletResponse()));
    assertNull(Camada.engineFor(null));
    // with one: they resolve through it
    Camada inert = Camada.configure(new Options().env(Map.of()));
    assertSame(inert, Camada.engineFor(null));
    assertEquals("", Camada.scriptTag(bare));
  }

  @Test
  void aHelperCallBeforeTheFirstRequestDoesNotPreEmptTheFiltersOptions() throws Exception {
    // The trap: a handler outside the filter's mapping calls Camada.track() first. Were the
    // helpers to build the default from System.getenv(), a filter handed Options would be bound
    // to that inert engine for the JVM's life.
    Camada.resetDefault();
    CamadaFilter filter = new CamadaFilter(new Options().env(Hosts.ENV).transport(analyst));
    MockHttpServletRequest bare = new MockHttpServletRequest();
    Camada.track(bare, "login_failed", "bob");
    assertEquals("", Camada.scriptTag(bare));
    assertNull(Camada.engineFor(null));
    MockHttpServletRequest req = ServletDriver.request(new Call("GET", "/"));
    MockHttpServletResponse res = new MockHttpServletResponse();
    filter.doFilter(req, res, (rq, rs) -> rs.getOutputStream().write("x".getBytes()));
    Camada built = filter.engine();
    try {
      assertFalse(built.disabled()); // built with the filter's options, not System.getenv()
      assertSame(built, Camada.getDefault());
      assertNotNull(res.getHeader("x-rid"));
    } finally {
      Camada.resetDefault();
    }
  }

  @Test
  void serveChallengeWritesThePageAndReturnsTrue() throws Exception {
    CamadaFilter filter = new CamadaFilter(engine);
    FilterChain chain =
        (rq, rs) -> {
          HttpServletRequest req = (HttpServletRequest) rq;
          HttpServletResponse res = (HttpServletResponse) rs;
          if (!Camada.serveChallenge(req, res)) {
            res.setStatus(200);
            res.getOutputStream().write("file".getBytes());
          }
        };
    MockHttpServletRequest req =
        ServletDriver.request(new Call("GET", "/export").header("accept", "text/html"));
    MockHttpServletResponse res = new MockHttpServletResponse();
    filter.doFilter(req, res, chain);
    assertEquals(403, res.getStatus());
    assertEquals("1", res.getHeader("x-camada-challenge"));
    assertTrue(res.getContentType().startsWith("text/html"));
    assertTrue(res.getContentAsString().contains("camada-f"));
    List<Map<String, Object>> evs = events();
    assertEquals(1, evs.size()); // one request, one event
    assertEquals("challenge", evs.get(0).get("blk"));
    // with a valid _cch the helper stands down
    String cch = engine.kit().issue(Hosts.PEER, engine.nowMs());
    MockHttpServletRequest ok =
        ServletDriver.request(
            new Call("GET", "/export")
                .header("accept", "text/html")
                .header("cookie", "_cch=" + cch));
    MockHttpServletResponse okRes = new MockHttpServletResponse();
    filter.doFilter(ok, okRes, chain);
    assertEquals(200, okRes.getStatus());
    assertEquals("file", okRes.getContentAsString());
    List<Map<String, Object>> all = events();
    assertEquals(2, all.size());
    assertEquals(200L, ((Number) all.get(1).get("st")).longValue());
    assertNull(all.get(1).get("blk"));
  }

  @Test
  void wrapsTheDefaultEngineLazily() throws Exception {
    Camada.resetDefault();
    CamadaFilter filter =
        new CamadaFilter(new Options().env(Map.of("CAMADA_DISABLED", "1", "CAMADA_KEY", "a.b")));
    MockHttpServletRequest req = ServletDriver.request(new Call("GET", "/"));
    MockHttpServletResponse res = new MockHttpServletResponse();
    filter.doFilter(req, res, (rq, rs) -> rs.getOutputStream().write("x".getBytes()));
    assertEquals("x", res.getContentAsString());
    assertTrue(Camada.getDefault().disabled());
    assertNull(res.getHeader("x-rid"));
  }

  @Test
  void aFailingRequestMappingFallsOpenToTheApp() throws Exception {
    MockHttpServletRequest req =
        new MockHttpServletRequest() {
          @Override
          public java.util.Enumeration<String> getHeaderNames() {
            throw new IllegalStateException("container bug");
          }
        };
    req.setRequestURI("/");
    MockHttpServletResponse res = new MockHttpServletResponse();
    new CamadaFilter(engine)
        .doFilter(req, res, (rq, rs) -> rs.getOutputStream().write("app".getBytes()));
    assertEquals("app", res.getContentAsString());
    assertEquals(200, res.getStatus());
  }

  @Test
  void statusWrapperReadsTheContainersResponse() throws IOException {
    // the status set on the container's own response (startAsync() hands the app that one)
    MockHttpServletResponse raw = new MockHttpServletResponse();
    StatusResponseWrapper w = new StatusResponseWrapper(raw);
    assertEquals(200, w.getStatus());
    raw.setStatus(202);
    assertEquals(202, w.getStatus());
    w.sendError(418);
    assertEquals(418, w.getStatus());
    // a host response that cannot say reads as 200 rather than taking the event down
    StatusResponseWrapper mute =
        new StatusResponseWrapper(
            new MockHttpServletResponse() {
              @Override
              public int getStatus() {
                throw new UnsupportedOperationException("no status here");
              }
            });
    assertEquals(200, mute.getStatus());
  }

  @Test
  void replayWrapperHandsBackHeadThenRest() throws IOException {
    MockHttpServletRequest req = new MockHttpServletRequest();
    req.setContent("hello world".getBytes());
    req.setCharacterEncoding("UTF-8");
    jakarta.servlet.ServletInputStream original = req.getInputStream();
    byte[] head = new byte[5];
    assertEquals(5, original.read(head));
    ReplayRequestWrapper w = new ReplayRequestWrapper(req, head, 5, original);
    jakarta.servlet.ServletInputStream in = w.getInputStream();
    assertTrue(in.isReady());
    assertFalse(in.isFinished());
    assertEquals("hello world", new String(in.readAllBytes()));
    assertTrue(in.isFinished());
    assertEquals(-1, in.read());
    assertSame(in, w.getInputStream()); // one stream per request, as the servlet spec expects
    assertThrows(IllegalStateException.class, () -> w.getReader());
    assertThrows(IllegalStateException.class, () -> in.setReadListener(null));
    MockHttpServletRequest req2 = new MockHttpServletRequest();
    req2.setContent("héllo".getBytes());
    req2.setCharacterEncoding("UTF-8");
    jakarta.servlet.ServletInputStream original2 = req2.getInputStream();
    byte[] head2 = new byte[3];
    assertEquals(3, original2.read(head2)); // "hé" is three bytes: the split lands mid-character
    ReplayRequestWrapper w2 = new ReplayRequestWrapper(req2, head2, 3, original2);
    assertEquals("héllo", w2.getReader().readLine());
    assertThrows(IllegalStateException.class, () -> w2.getInputStream());
  }
}
