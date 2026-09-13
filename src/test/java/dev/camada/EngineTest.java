package dev.camada;

import static dev.camada.FakeAnalyst.ALLOWED_IP;
import static dev.camada.FakeAnalyst.BLOCKED_HEADER;
import static dev.camada.FakeAnalyst.BLOCKED_HEADER_VALUE;
import static dev.camada.FakeAnalyst.BLOCKED_IP;
import static dev.camada.FakeAnalyst.BLOCKED_UA;
import static dev.camada.FakeAnalyst.CHALLENGED_IP;
import static dev.camada.FakeAnalyst.RULE_BLOCKED_IP;
import static dev.camada.FakeAnalyst.RULE_BLOCKED_PATH;
import static dev.camada.FakeAnalyst.SKIP_PATH;
import static dev.camada.FakeAnalyst.WARN_UA;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.Hosts.AppHandler;
import dev.camada.Hosts.Call;
import dev.camada.Hosts.Reply;
import dev.camada.Hosts.ServletDriver;
import dev.camada.challenge.ChallengeTest;
import dev.camada.snapshot.Matcher.MatchInput;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * The engine through the servlet host: inline enforcement, ordered custom rules, the challenge, the
 * first-party beacon, request capture, app-context events, and the fail-open envelope. The case
 * list mirrors camada-python's test_engine.py (which drives WSGI and ASGI; Java has the one host).
 */
class EngineTest {
  static final String[] HTML = {"accept", "text/html,*/*", "sec-fetch-dest", "document"};

  FakeAnalyst analyst;
  final List<Camada> engines = new ArrayList<>();

  @BeforeEach
  void fresh() {
    analyst = new FakeAnalyst();
  }

  @AfterEach
  void stopAll() {
    for (Camada e : engines) {
      e.stop();
    }
  }

  static Call html(Call c) {
    return c.header(HTML[0], HTML[1]).header(HTML[2], HTML[3]);
  }

  static Call xff(Call c, String addr) {
    return c.header("x-forwarded-for", addr);
  }

  static void hops1(FakeAnalyst a) {
    a.config.put("trusted_proxy", Map.of("mode", "hops", "hops", 1L));
  }

  static long num(Map<String, Object> ev, String key) {
    return ((Number) ev.get(key)).longValue();
  }

  static String nonceOf(String page) {
    return page.split("name=\"nonce\" value=\"")[1].split("\"")[0];
  }

  /** One engine + one host per test, loaded unless asked otherwise. */
  final class Host {
    final Camada engine;
    final ServletDriver drv;

    Host(Map<String, String> env, AppHandler handler, boolean load, Options opts) {
      engine = Hosts.engineWith(analyst, env, opts);
      engines.add(engine);
      drv = new ServletDriver(engine, handler);
      if (load && engine.snapshot() != null) {
        Hosts.loaded(engine);
      }
    }

    Host() {
      this(null, Hosts.HELLO, true, null);
    }

    Host(Map<String, String> env) {
      this(env, Hosts.HELLO, true, null);
    }

    Host(AppHandler handler) {
      this(null, handler, true, null);
    }

    Reply call(Call c) {
      try {
        return drv.call(c);
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }

    Reply get(String path) {
      return call(new Call("GET", path));
    }

    List<Map<String, Object>> events() {
      assertNotNull(engine.queue());
      engine.queue().flush();
      return analyst.allEvents();
    }

    List<HttpServletRequest> seen() {
      return drv.seen;
    }

    Context ctx(int i) {
      return (Context) seen().get(i).getAttribute("camada");
    }
  }

  @Nested
  class InlineBlocking {
    @Test
    void answers403BeforeTheAppAndStillShipsTheEvent() {
      Host h = new Host(Map.of("CAMADA_TRUSTED_PROXY", "hops:1"));
      Reply r = h.call(xff(new Call("GET", "/admin?x=1"), BLOCKED_IP));
      assertEquals(403, r.status());
      assertEquals("Forbidden", r.text());
      assertEquals("ip4", r.header("x-block-reason"));
      assertEquals(analyst.meta().get("version"), r.header("x-block-version"));
      assertEquals("text/plain", r.header("content-type"));
      assertNull(r.header("x-block-rule"));
      assertNull(r.header("x-rid"));
      assertTrue(h.seen().isEmpty());
      List<Map<String, Object>> evs = h.events();
      assertEquals(1, evs.size());
      Map<String, Object> ev = evs.get(0);
      assertEquals(403L, num(ev, "st"));
      assertEquals("ip4", ev.get("blk"));
      assertEquals(BLOCKED_IP, ev.get("ip"));
      assertEquals("/admin", ev.get("p"));
      assertEquals("sdk-java", ev.get("tap"));
      assertFalse(ev.containsKey("rl"));
    }

    @Test
    void ignoresASpoofedXffWithoutTrustedProxyConfig() {
      Host h = new Host();
      assertEquals(200, h.call(xff(new Call("GET", "/"), BLOCKED_IP)).status());
      assertEquals(403, h.call(new Call("GET", "/").peer(BLOCKED_IP)).status());
    }

    @Test
    void serverDeliveredTrustedProxyAppliesWhenNoLocalOverride() {
      hops1(analyst);
      Host h = new Host();
      assertEquals(403, h.call(xff(new Call("GET", "/"), BLOCKED_IP)).status());
    }

    @Test
    void failsOpenWhileCold() {
      analyst.snapshotDown = true;
      Host h = new Host(null, Hosts.HELLO, false, null);
      assertEquals(200, h.call(new Call("GET", "/").peer(BLOCKED_IP)).status());
      assertEquals(1, h.seen().size());
    }

    @Test
    void honoursTheAllowSideOverAWiderBlock() {
      analyst.container = "v4";
      Host h = new Host();
      assertEquals(403, h.call(new Call("GET", "/").peer("10.0.0.9")).status());
      assertEquals(200, h.call(new Call("GET", "/").peer(ALLOWED_IP)).status());
    }
  }

  @Nested
  class SdkIdentity {
    @Test
    void sendsXCamadaSdkOnPollsAndBatches() {
      Host h = new Host();
      h.get("/");
      h.events();
      assertTrue(analyst.sdkHeaders.size() >= 2);
      for (String s : analyst.sdkHeaders) {
        assertEquals(Version.SDK_ID, s);
      }
    }

    @Test
    void asksForV5ByDefaultAndOptsOutAt3() {
      new Host();
      new Host(null, Hosts.HELLO, true, new Options().snapshotVersion(3));
      assertEquals(List.of("5", ""), analyst.snapshotVersions.subList(0, 2));
    }
  }

  @Nested
  class Capture {
    @Test
    void capturesOnFinishWithStatusLatencySessionAndRid() {
      Host h = new Host(req -> Reply.of(201, "made".getBytes(), "x-app", "1"));
      Reply r =
          h.call(
              new Call("POST", "/things?q=1&token=secret")
                  .header("user-agent", "UA/1")
                  .header("accept", "*/*")
                  .body("{}"));
      assertEquals(201, r.status());
      assertEquals("made", r.text());
      assertEquals("1", r.header("x-app"));
      String rid = r.header("x-rid");
      assertNotNull(rid);
      assertEquals(36, rid.length());
      String cookie = r.header("set-cookie");
      assertNotNull(cookie);
      assertTrue(cookie.startsWith("_sfp="));
      assertTrue(
          cookie.contains("HttpOnly")
              && cookie.contains("SameSite=Lax")
              && !cookie.contains("Secure"));
      List<Map<String, Object>> evs = h.events();
      assertEquals(1, evs.size());
      Map<String, Object> ev = evs.get(0);
      assertEquals(rid, ev.get("rid"));
      assertEquals(cookie.substring(5).split(";")[0], ev.get("sid"));
      assertEquals(1L, num(ev, "ns"));
      assertEquals(201L, num(ev, "st"));
      assertTrue(num(ev, "dur") >= 0);
      assertEquals("POST", ev.get("m"));
      assertEquals("/things", ev.get("p"));
      assertEquals("?q=1&token=~r", ev.get("q"));
      assertEquals("UA/1", ev.get("ua"));
      assertEquals(Hosts.PEER, ev.get("ip"));
      assertEquals("HTTP/1.1", ev.get("proto"));
      assertEquals("x.test", ev.get("h"));
      assertFalse(ev.containsKey("blk"));
      assertFalse(ev.containsKey("wrn"));
    }

    @Test
    void reusesTheSessionCookieAndMarksHttpsSecure() {
      Host h = new Host();
      Reply r = h.call(new Call("GET", "/").header("cookie", "a=1; _sfp=sess-1; b=2").https(true));
      assertNull(r.header("set-cookie"));
      Reply r2 = h.call(new Call("GET", "/").https(true));
      assertTrue(r2.header("set-cookie").contains("; Secure"));
      Reply r3 = h.call(new Call("GET", "/").header("x-forwarded-proto", "https"));
      assertTrue(r3.header("set-cookie").contains("; Secure"));
      Map<String, Object> ev = h.events().get(0);
      assertEquals("sess-1", ev.get("sid"));
      assertEquals(0L, num(ev, "ns"));
    }

    @Test
    void keepsTheAppsOwnCookies() {
      Host h =
          new Host(
              req ->
                  Reply.of(200, new byte[0], "set-cookie", "app=1; Path=/", "set-cookie", "b=2"));
      Reply r = h.get("/");
      List<String> cookies = r.headersNamed("set-cookie");
      assertEquals(3, cookies.size());
      assertTrue(cookies.stream().anyMatch(c -> c.startsWith("app=1")));
      assertTrue(cookies.stream().anyMatch(c -> c.startsWith("b=2")));
      assertTrue(cookies.stream().anyMatch(c -> c.startsWith("_sfp=")));
    }

    @Test
    void honoursExcludeAndSampleAndNeverCapturesCredentials() {
      analyst.config.put("exclude", List.of("/health"));
      Host h = new Host();
      h.get("/health/live");
      h.call(
          new Call("GET", "/api")
              .header("authorization", "Bearer very-secret")
              .header("cookie", "s=1; t=2"));
      List<Map<String, Object>> evs = h.events();
      assertEquals(1, evs.size());
      Map<String, Object> ev = evs.get(0);
      assertEquals("/api", ev.get("p"));
      assertEquals("Bearer", ev.get("auth"));
      assertEquals(2L, num(ev, "ck"));
      String dump = Json.stringify(ev);
      assertFalse(dump.contains("very-secret"));
      assertFalse(dump.contains("s=1"));
      analyst.config.put("sample", 0L);
      h.engine.snapshot().refresh();
      h.get("/api");
      assertEquals(1, h.events().size());
    }

    @Test
    void exposesRidSidIpToTheApp() {
      Host h = new Host();
      Reply r = h.get("/");
      Context ctx = h.ctx(0);
      assertEquals(r.header("x-rid"), ctx.rid());
      assertEquals(Hosts.PEER, ctx.ip());
      assertNotNull(ctx.sid());
      assertTrue(Camada.engineFor(ctx) == h.engine);
    }

    @Test
    void anAppExceptionShipsSt500AndPropagates() {
      Host h =
          new Host(
              req -> {
                throw new RuntimeException("app bug");
              });
      assertThrows(RuntimeException.class, () -> h.drv.call(new Call("GET", "/crash")));
      List<Map<String, Object>> evs = h.events();
      assertEquals(1, evs.size());
      assertEquals("/crash", evs.get(0).get("p"));
      assertEquals(500L, num(evs.get(0), "st"));
    }

    @Test
    void theRoutePatternReachesTheEventWhenTheHostSetsIt() {
      Host h =
          new Host(
              req -> {
                req.setAttribute(
                    "org.springframework.web.servlet.HandlerMapping.bestMatchingPattern",
                    "/items/{id}");
                return Reply.of(200, new byte[0]);
              });
      h.get("/items/7");
      assertEquals("/items/{id}", h.events().get(0).get("rt"));
      Host plain = new Host();
      plain.get("/x");
      List<Map<String, Object>> all =
          plain.events(); // the analyst is shared: the last row is plain's
      assertFalse(all.get(all.size() - 1).containsKey("rt"));
    }
  }

  @Nested
  class Track {
    @Test
    void trackShipsAnAppContextEventWithAHashedUid() {
      Host[] holder = new Host[1];
      Host h =
          new Host(
              req -> {
                holder[0].engine.track(
                    (Context) req.getAttribute("camada"), "login_failed", "alice@example.com");
                return Reply.of(401, new byte[0]);
              });
      holder[0] = h;
      Reply r = h.call(new Call("POST", "/login").body("x=1"));
      List<Map<String, Object>> evs = h.events();
      Map<String, Object> tracked =
          evs.stream().filter(e -> e.get("et") != null).findFirst().orElseThrow();
      assertEquals("login_failed", tracked.get("et"));
      assertEquals("sdk-java", tracked.get("tap"));
      assertEquals(r.header("x-rid"), tracked.get("rid"));
      assertEquals(Redact.hashUserId("alice@example.com", "tok-test"), tracked.get("uid"));
      assertFalse(Json.stringify(evs).contains("alice"));
      assertEquals(Hosts.PEER, tracked.get("ip"));
      assertFalse(tracked.containsKey("p"));
      assertEquals(
          List.of("tap", "et", "uid", "rid", "sid", "ip", "ts"), new ArrayList<>(tracked.keySet()));
    }

    @Test
    void trackWithoutAUserAndWithoutContext() {
      Host h = new Host();
      h.engine.track((Context) null, "signup", null);
      List<Map<String, Object>> evs = h.events();
      assertEquals(1, evs.size());
      assertEquals("signup", evs.get(0).get("et"));
      assertNull(evs.get(0).get("uid"));
      assertNull(evs.get(0).get("rid"));
    }
  }

  @Nested
  class Beacon {
    @Test
    void servesTheScriptAndBatchesFpAsASigRowWithTheResolvedIp() {
      hops1(analyst);
      Host h = new Host();
      Reply js = h.get("/_cam/b.js");
      assertEquals(200, js.status());
      assertEquals("application/javascript", js.header("content-type"));
      assertTrue(js.text().contains("@camada/browser"));
      assertEquals("public, max-age=3600", js.header("cache-control"));
      assertEquals(BeaconJs.BYTES.length, js.body().length);
      String body =
          "{\"sdk\":\"@camada/browser/0.2.0\",\"rid\":\"r-1\",\"ip\":\"9.9.9.9\",\"tap\":\"proxy\",\"scr\":\"1x1\"}";
      Reply fp =
          h.call(
              new Call("POST", "/_cam/fp")
                  .header("x-forwarded-for", "198.18.0.5")
                  .header("content-type", "application/json")
                  .body(body));
      assertEquals(204, fp.status());
      assertEquals("no-store", fp.header("cache-control"));
      assertTrue(h.seen().isEmpty());
      List<Map<String, Object>> evs = h.events();
      assertEquals(1, evs.size());
      Map<String, Object> row = evs.get(0);
      assertEquals(1L, num(row, "sig"));
      assertEquals("198.18.0.5", row.get("ip"));
      assertEquals("sdk-java", row.get("tap"));
      assertEquals("1x1", row.get("scr"));
      assertEquals("r-1", row.get("rid"));
      assertEquals("@camada/browser/0.2.0", row.get("sdk"));
    }

    @Test
    void dropsJunkBodiesInsteadOfShippingThem() {
      Host h = new Host();
      for (String junk : new String[] {"not json", "[1,2]", "42", ""}) {
        assertEquals(204, h.call(new Call("POST", "/_cam/fp").body(junk)).status(), junk);
      }
      assertEquals(0, h.events().size());
    }

    @Test
    void rejectsOversizedPostsDeclaredOrActual() {
      Host h = new Host();
      assertEquals(
          413, h.call(new Call("POST", "/_cam/fp").body("{}").contentLength(40000)).status());
      assertEquals(
          413, h.call(new Call("POST", "/_cam/fp").body("{" + " ".repeat(33000) + "}")).status());
      assertEquals(0, h.events().size());
    }

    @Test
    void fallsThroughToTheAppWhenTheTenantDisabledTheBeacon() {
      analyst.config.put("beacon", false);
      Host h = new Host();
      assertEquals("hello", h.get("/_cam/b.js").text());
      assertEquals("hello", h.call(new Call("POST", "/_cam/fp").body("{}")).text());
      assertEquals("", h.engine.scriptTag(h.ctx(0)));
    }

    @Test
    void scriptTagCarriesTheRid() {
      Host h = new Host();
      Reply r = h.get("/");
      assertEquals(
          "<script src=\"/_cam/b.js?r=" + r.header("x-rid") + "\" async></script>",
          h.engine.scriptTag(h.ctx(0)));
      assertEquals(
          "<script src=\"/_cam/b.js\" async></script>", h.engine.scriptTag((Context) null));
    }

    @Test
    void enforcementComesBeforeTheBeaconEndpoints() {
      Host h = new Host();
      assertEquals(403, h.call(new Call("GET", "/_cam/b.js").peer(BLOCKED_IP)).status());
    }

    @Test
    void thePathsMove() {
      Host h =
          new Host(
              null,
              Hosts.HELLO,
              true,
              new Options().scriptPath("/static/c.js").fpPath("/static/fp"));
      assertEquals("application/javascript", h.get("/static/c.js").header("content-type"));
      assertEquals(204, h.call(new Call("POST", "/static/fp").body("{}")).status());
      assertEquals("hello", h.get("/_cam/b.js").text());
      assertEquals(
          "<script src=\"/static/c.js\" async></script>", h.engine.scriptTag((Context) null));
    }
  }

  @Nested
  class Rules {
    @BeforeEach
    void v5() {
      analyst.container = "v5";
      hops1(analyst);
    }

    @Test
    void skipRuleBeatsTheWiderBlock() {
      Host h = new Host();
      assertEquals(200, h.call(xff(new Call("GET", SKIP_PATH), BLOCKED_IP)).status());
      Map<String, Object> ev = h.events().get(0);
      assertFalse(ev.containsKey("blk"));
      assertFalse(ev.containsKey("wrn"));
    }

    @Test
    void blocksByRuleWithXBlockRuleAndShipsRl() {
      Host h = new Host();
      Reply r = h.call(xff(new Call("GET", "/"), RULE_BLOCKED_IP));
      assertEquals(403, r.status());
      assertEquals("rule", r.header("x-block-reason"));
      assertEquals("builtin:block", r.header("x-block-rule"));
      Map<String, Object> ev = h.events().get(0);
      assertEquals("rule", ev.get("blk"));
      assertEquals("builtin:block", ev.get("rl"));
    }

    @Test
    void blocksByPathUaAndHeaderRules() {
      Host h = new Host();
      assertEquals("cr_00000000000c", h.get(RULE_BLOCKED_PATH).header("x-block-rule"));
      assertEquals(403, h.call(new Call("GET", "/").header("user-agent", BLOCKED_UA)).status());
      // any spelling of the header name
      assertEquals(
          403,
          h.call(new Call("GET", "/").header(BLOCKED_HEADER.toUpperCase(), BLOCKED_HEADER_VALUE))
              .status());
      assertEquals(200, h.call(new Call("GET", "/").header(BLOCKED_HEADER, "other")).status());
      assertEquals(200, h.get("/").status());
    }

    @Test
    void warnPassesAndStampsWrn() {
      Host h = new Host();
      assertEquals(200, h.call(new Call("GET", "/").header("user-agent", WARN_UA)).status());
      Map<String, Object> ev = h.events().get(0);
      assertEquals("cr_00000000000e", ev.get("wrn"));
      assertEquals(200L, num(ev, "st"));
    }

    @Test
    void stillEnforcesAgainstAnAnalystThatOnlyPublishesV3() {
      analyst.container = "v3";
      Host h = new Host();
      assertEquals(403, h.call(xff(new Call("GET", "/"), BLOCKED_IP)).status());
      // a rule-only signal: v3 carries no rules
      assertEquals(200, h.call(new Call("GET", "/").header("user-agent", BLOCKED_UA)).status());
    }
  }

  @Nested
  class Challenge {
    @BeforeEach
    void v4() {
      analyst.container = "v4";
    }

    @Test
    void servesThePageForAnHtmlNavigationAndShipsBlkChallenge() {
      Host h = new Host();
      Reply r = h.call(html(new Call("GET", "/account?tab=1")).peer(CHALLENGED_IP));
      assertEquals(403, r.status());
      assertEquals("text/html; charset=utf-8", r.header("content-type"));
      assertEquals("1", r.header("x-camada-challenge"));
      assertEquals("no-store", r.header("cache-control"));
      assertTrue(r.text().contains("action=\"/__camada/challenge\""));
      assertTrue(r.text().contains("name=\"to\" value=\"/account?tab=1\""));
      assertTrue(h.seen().isEmpty());
      Map<String, Object> ev = h.events().get(0);
      assertEquals(403L, num(ev, "st"));
      assertEquals("challenge", ev.get("blk"));
      assertEquals("/account", ev.get("p"));
    }

    @Test
    void answersJsonForANonHtmlRequest() {
      Host h = new Host();
      Reply r =
          h.call(new Call("GET", "/api").header("accept", "application/json").peer(CHALLENGED_IP));
      assertEquals(403, r.status());
      assertEquals("application/json", r.header("content-type"));
      assertEquals("{\"error\":\"challenge_required\"}", r.text());
      Reply r2 =
          h.call(
              new Call("GET", "/api")
                  .header("accept", "text/html")
                  .header("sec-fetch-dest", "empty")
                  .peer(CHALLENGED_IP));
      assertEquals("application/json", r2.header("content-type"));
    }

    @Test
    void blocksOutrightRatherThanChallengingABlockedIp() {
      Host h = new Host();
      Reply r = h.call(html(new Call("GET", "/")).peer(BLOCKED_IP));
      assertEquals(403, r.status());
      assertNull(r.header("x-camada-challenge"));
    }

    @Test
    void verifySetsCchRedirectsBackAndShipsCh1() {
      Host h = new Host();
      String page = h.call(html(new Call("GET", "/back?x=1")).peer(CHALLENGED_IP)).text();
      String nonce = nonceOf(page);
      String form =
          "nonce=" + nonce + "&solution=" + ChallengeTest.solve(nonce) + "&to=%2Fback%3Fx%3D1";
      Reply r =
          h.call(
              new Call("POST", "/__camada/challenge")
                  .header("content-type", "application/x-www-form-urlencoded")
                  .body(form)
                  .peer(CHALLENGED_IP));
      assertEquals(302, r.status());
      assertEquals("/back?x=1", r.header("location"));
      assertEquals("no-store", r.header("cache-control"));
      String cookie = r.header("set-cookie");
      assertNotNull(cookie);
      assertTrue(cookie.startsWith("_cch=") && cookie.contains("HttpOnly"));
      List<Map<String, Object>> evs = h.events();
      Map<String, Object> last = evs.get(evs.size() - 1);
      assertEquals(200L, num(last, "st"));
      assertEquals(1L, num(last, "ch"));
      assertEquals("/__camada/challenge", last.get("p"));
      // the holder of a valid _cch passes; a cookie minted for another ip does not
      String pair = cookie.split(";")[0];
      assertEquals(
          200,
          h.call(html(new Call("GET", "/back")).header("cookie", pair).peer(CHALLENGED_IP))
              .status());
      // not challenged at all
      assertEquals(
          200,
          h.call(html(new Call("GET", "/back")).header("cookie", pair).peer("192.0.2.21"))
              .status());
      String tampered = "_cch=" + pair.substring(5).replaceFirst("0", "1");
      assertEquals(
          403,
          h.call(html(new Call("GET", "/back")).header("cookie", tampered).peer(CHALLENGED_IP))
              .status());
    }

    @Test
    void wrongSolutionOrForgedNonceReservesThePage() {
      Host h = new Host();
      String nonce = nonceOf(h.call(html(new Call("GET", "/")).peer(CHALLENGED_IP)).text());
      Reply r =
          h.call(
              new Call("POST", "/__camada/challenge")
                  .body("nonce=" + nonce + "&solution=1&to=%2F")
                  .peer(CHALLENGED_IP));
      assertEquals(403, r.status());
      assertNull(r.header("set-cookie"));
      assertTrue(r.text().contains("camada-f"));
      String forged = "f".repeat(32);
      Reply r2 =
          h.call(
              new Call("POST", "/__camada/challenge")
                  .body("nonce=" + forged + "&solution=" + ChallengeTest.solve(forged) + "&to=%2F")
                  .peer(CHALLENGED_IP));
      assertEquals(403, r2.status());
      assertNull(r2.header("set-cookie"));
    }

    @Test
    void neverRedirectsOffSite() {
      Host h = new Host();
      String nonce = h.engine.kit().nonce(CHALLENGED_IP, h.engine.nowMs());
      Reply r =
          h.call(
              new Call("POST", "/__camada/challenge")
                  .body(
                      "nonce="
                          + nonce
                          + "&solution="
                          + ChallengeTest.solve(nonce)
                          + "&to=https%3A%2F%2Fevil")
                  .peer(CHALLENGED_IP));
      assertEquals(302, r.status());
      assertEquals("/", r.header("location"));
    }

    @Test
    void refusesAnOversizedVerifyBody() {
      Host h = new Host();
      assertEquals(
          413,
          h.call(
                  new Call("POST", "/__camada/challenge")
                      .body("a=" + "b".repeat(5000))
                      .peer(CHALLENGED_IP))
              .status());
    }

    @Test
    void noIpMeansNoChallenge() {
      Host h = new Host();
      assertEquals(200, h.call(html(new Call("GET", "/")).peer(null)).status());
    }

    @Test
    void switchedOffByEnvOrOption() {
      assertEquals(
          200,
          new Host(Map.of("CAMADA_CHALLENGE", "0"))
              .call(html(new Call("GET", "/")).peer(CHALLENGED_IP))
              .status());
      assertEquals(
          200,
          new Host(null, Hosts.HELLO, true, new Options().challenge(false))
              .call(html(new Call("GET", "/")).peer(CHALLENGED_IP))
              .status());
    }

    @Test
    void serveChallengeOnDemand() {
      Host[] holder = new Host[1];
      Host h =
          new Host(
              req -> {
                Answer answer =
                    holder[0].engine.serveChallenge((Context) req.getAttribute("camada"));
                if (answer != null) {
                  return new Reply(answer.status(), answer.headers(), answer.body());
                }
                return Reply.of(200, "secret page".getBytes());
              });
      holder[0] = h;
      Reply r = h.call(html(new Call("GET", "/challenge-me")));
      assertEquals(403, r.status());
      assertTrue(r.text().contains("camada-f"));
      List<Map<String, Object>> evs = h.events();
      assertEquals(1, evs.size()); // one request, one event
      assertEquals("challenge", evs.get(0).get("blk"));
      String nonce = nonceOf(r.text());
      Reply ok =
          h.call(
              new Call("POST", "/__camada/challenge")
                  .body(
                      "nonce="
                          + nonce
                          + "&solution="
                          + ChallengeTest.solve(nonce)
                          + "&to=%2Fchallenge-me"));
      String cookie = ok.header("set-cookie").split(";")[0];
      assertEquals(
          "secret page",
          h.call(html(new Call("GET", "/challenge-me")).header("cookie", cookie)).text());
      assertNull(h.engine.serveChallenge((Context) null));
    }
  }

  @Nested
  class FailOpen {
    @Test
    void keepsServingWhenIngestIsDown() {
      analyst.ingestDown = true;
      Host h = new Host();
      assertEquals(200, h.get("/").status());
      assertEquals(0, h.events().size());
      assertEquals(1, h.engine.queue().dropped());
    }

    @Test
    void disabledBypassesTheSdkEntirely() {
      Host h = new Host(Map.of("CAMADA_DISABLED", "1"), Hosts.HELLO, false, null);
      assertNull(h.engine.snapshot());
      assertTrue(h.engine.disabled());
      Reply r = h.call(new Call("GET", "/").peer(BLOCKED_IP));
      assertEquals(200, r.status());
      assertNull(r.header("x-rid"));
      assertTrue(analyst.snapshotRequests.isEmpty());
      assertEquals("hello", h.get("/_cam/b.js").text());
      assertNull(h.engine.wantsBody("POST", "/_cam/fp"));
    }

    @Test
    void staysInertWithoutCredentials() {
      Host h = new Host(Map.of("CAMADA_KEY", ""), Hosts.HELLO, false, null);
      assertNull(h.engine.env());
      assertEquals(200, h.call(new Call("GET", "/").peer(BLOCKED_IP)).status());
      assertEquals("", h.engine.scriptTag((Context) null));
      assertNull(h.engine.serveChallenge((Context) null));
      h.engine.track((Context) null, "x", null);
      assertTrue(analyst.snapshotRequests.isEmpty());
      assertNull(h.engine.wantsBody("POST", "/_cam/fp"));
    }

    @Test
    void aCamadaBugCostsTheJoinNotTheRequest() {
      Camada broken =
          new Camada(new Options().env(Hosts.ENV).transport(analyst)) {
            @Override
            protected Result decide(Req req, byte[] body) {
              throw new RuntimeException("sdk bug");
            }
          };
      engines.add(broken);
      Hosts.loaded(broken);
      ServletDriver d = new ServletDriver(broken);
      Reply r;
      try {
        r = d.call(new Call("GET", "/").peer(BLOCKED_IP));
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
      assertEquals(200, r.status());
      assertEquals("hello", r.text());
      assertNull(r.header("x-rid"));
    }

    @Test
    void wantsBodyOnlyForCamadasOwnPosts() {
      Host h = new Host();
      assertEquals(Constants.FP_MAX, h.engine.wantsBody("POST", "/_cam/fp"));
      assertEquals(Constants.BODY_MAX, h.engine.wantsBody("POST", "/__camada/challenge"));
      assertNull(h.engine.wantsBody("GET", "/_cam/fp"));
      assertNull(h.engine.wantsBody("POST", "/login"));
      analyst.config.put("beacon", false);
      h.engine.snapshot().refresh();
      assertNull(h.engine.wantsBody("POST", "/_cam/fp"));
    }
  }

  @Nested
  class DefaultEngine {
    @AfterEach
    void reset() {
      Camada.resetDefault();
    }

    @Test
    void theReadmeWarmUpWaitsForTheBootPoll() {
      // The README's startup recipe: getDefault() has already kicked the boot poll, so a plain
      // refresh() finds the lock held and returns cold; waiting on verdict() until it is not cold
      // is what warms it — and warmUp() wraps exactly that loop.
      Camada engine = Camada.configure(new Options().env(Hosts.ENV).transport(analyst));
      assertNotNull(engine.snapshot());
      assertTrue(engine.warmUp(5000));
      assertTrue(engine.snapshot().verdict(MatchInput.ip(BLOCKED_IP)).block());
      assertTrue(Camada.getDefault() == engine);
      assertTrue(
          Camada.getDefault(new Options()) == engine); // options are for the first build only
    }

    @Test
    void warmUpIsBoundedAndInertWithoutAnEngine() {
      analyst.snapshotDown = true;
      Camada cold = Camada.configure(new Options().env(Hosts.ENV).transport(analyst));
      assertFalse(cold.warmUp(30));
      Camada inert = Camada.configure(new Options().env(Map.of()));
      assertNull(inert.snapshot());
      assertFalse(inert.warmUp(30));
    }

    @Test
    void configureReplacesAndStopsTheOldEngine() {
      Camada first = Camada.configure(new Options().env(Hosts.ENV).transport(analyst));
      Camada second = Camada.configure(new Options().env(Hosts.ENV).transport(analyst));
      assertTrue(first != second);
      assertTrue(Camada.getDefault() == second);
      first.queue().push(Map.of("i", 1L));
      Hosts.sleep(30);
      assertEquals(0, analyst.events.size()); // the stopped queue never flushes on its own
    }
  }
}
