package dev.camada;

import dev.camada.Config.RemoteConfig;
import dev.camada.Config.TrustedProxy;
import dev.camada.challenge.Format;
import dev.camada.challenge.Kit;
import dev.camada.challenge.Page;
import dev.camada.events.Builder;
import dev.camada.events.Builder.RequestInfo;
import dev.camada.events.Queue;
import dev.camada.snapshot.Client;
import dev.camada.snapshot.Matcher.MatchInput;
import dev.camada.snapshot.Matcher.MatchResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.IntConsumer;

/**
 * The engine: the host-neutral request handling every adapter delegates to (the Java twin of
 * camada-python's engine.py and {@code @camada/node}'s Camada.handle). An adapter turns its request
 * into a {@link Req}, asks {@link #wantsBody} and reads at most that many bytes, then calls {@link
 * #handle}: an {@link Answer} means camada fully answered the request (block, challenge, verify,
 * beacon endpoints); a {@link Passed} means run the app, stamp the rid header and session cookie on
 * its response, and call onFinish(status) once when it is done. Everything runs inside the
 * fail-open envelope: a camada bug must never 5xx the customer, and CAMADA_DISABLED=1 bypasses the
 * SDK entirely.
 *
 * <p>The integrations share one lazy default engine ({@link #getDefault()}), built from the
 * environment on the first request through the filter; {@link #configure} replaces it for tests and
 * explicit wiring.
 */
public class Camada {
  private static volatile Camada defaultEngine;

  private final Map<String, String> source;
  private final String scriptPath;
  private final String fpPath;
  private final String challengePath;
  private final boolean challengeOn;
  private final Env env;
  private final Client snap;
  private final Queue queue;
  private final Kit kit;

  public Camada() {
    this(new Options());
  }

  public Camada(Options o) {
    source = o.env() != null ? o.env() : System.getenv();
    scriptPath = o.scriptPath();
    fpPath = o.fpPath();
    challengePath = o.challengePath();
    challengeOn = o.challenge() && !"0".equals(source.get("CAMADA_CHALLENGE"));
    env = Env.resolve(source);
    if (env == null || "1".equals(source.get(Constants.KILL_SWITCH_ENV))) {
      snap = null; // unconfigured or killed at boot: no threads, no exit hooks, truly silent
      queue = null;
      kit = null;
      return;
    }
    Client c =
        new Client(env.snapshotUrl(), env.snapToken())
            .mode(env.serverless() ? Client.Mode.LAZY : Client.Mode.TIMER)
            .sdk(Version.SDK_ID)
            .snapshotVersion(o.snapshotVersion());
    if (o.refreshS() != null) {
      c.refreshS(o.refreshS());
    }
    Queue q = new Queue(env.ingestUrl(), env.ingestToken()).sdk(Version.SDK_ID);
    if (o.transport() != null) {
      c.transport(o.transport()); // threaded into the snapshot client and event queue (tests)
      q.transport(o.transport());
    }
    snap = c;
    queue = q;
    kit = new Kit(env.secret());
    snap.start();
    queue.installExitFlush();
  }

  // ---- the default engine ----

  /** The lazy singleton wired from the environment on first use (what the integrations share). */
  public static Camada getDefault() {
    return getDefault(null);
  }

  /** The default engine, built with {@code opts} if this is the call that builds it. */
  public static Camada getDefault(Options opts) {
    Camada d = defaultEngine;
    if (d == null) {
      synchronized (Camada.class) {
        d = defaultEngine;
        if (d == null) {
          d = create(opts != null ? opts : new Options());
          defaultEngine = d;
        }
      }
    }
    return d;
  }

  /** Replaces the default engine (stopping the old one) — for tests and explicit wiring. */
  public static synchronized Camada configure(Options opts) {
    Camada old = defaultEngine;
    if (old != null) {
      old.stop();
    }
    Camada c = create(opts != null ? opts : new Options());
    defaultEngine = c;
    return c;
  }

  /** Stops and forgets the default engine, so the next getDefault() builds afresh (tests). */
  public static synchronized void resetDefault() {
    Camada old = defaultEngine;
    defaultEngine = null;
    if (old != null) {
      old.stop();
    }
  }

  /**
   * The engine that produced a request context, else the default as it stands, else null: what the
   * helpers resolve through. A peek, never a build — the default is built once, by the first
   * caller, with that caller's options; a helper running before the filter's first request (a
   * handler outside its mapping, say) must not build an inert default from System.getenv() that a
   * filter handed Options is then bound to for the JVM's life.
   */
  public static Camada engineFor(Context ctx) {
    return ctx != null && ctx.engine != null ? ctx.engine : defaultEngine;
  }

  private static Camada create(Options opts) {
    Camada c = new Camada(opts);
    if (c.env == null) {
      Guarded.logRateLimited(
          "CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive");
    }
    return c;
  }

  // ---- accessors ----

  /** The resolved environment, or null when the engine is inert. */
  public Env env() {
    return env;
  }

  /** The snapshot client, or null when the engine is inert or killed at boot. */
  public Client snapshot() {
    return snap;
  }

  public Queue queue() {
    return queue;
  }

  public Kit kit() {
    return kit;
  }

  public boolean disabled() {
    return env == null || "1".equals(source.get(Constants.KILL_SWITCH_ENV));
  }

  public long nowMs() {
    return Builder.nowMs();
  }

  /**
   * The README's startup recipe: waits, bounded, until the boot poll has landed. True when the
   * engine is warm; false when it is inert, killed, or the analyst never answered within the budget
   * (the app still fails open).
   */
  public boolean warmUp(long timeoutMs) {
    if (snap == null) {
      return false;
    }
    long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
    while ("cold".equals(snap.verdict(MatchInput.ip("0.0.0.0")).reason())) {
      if (System.nanoTime() >= deadline) {
        return false;
      }
      try {
        Thread.sleep(10);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return false;
      }
    }
    return true;
  }

  private TrustedProxy trustedProxy() {
    if (env != null && env.trustedProxy() != null) {
      return env.trustedProxy(); // explicit local override wins
    }
    RemoteConfig cfg = snap != null ? snap.config() : null;
    return cfg != null ? cfg.trustedProxy() : null;
  }

  private boolean beaconEnabled() {
    if (snap == null) {
      return false;
    }
    RemoteConfig cfg = snap.config();
    return cfg == null || !Boolean.FALSE.equals(cfg.beacon());
  }

  private String ip(Req req) {
    return Ip.resolveClientIp(req.peer(), req.header("x-forwarded-for"), trustedProxy());
  }

  static String cookieValue(String cookie, String name) {
    String src = "; " + (cookie == null ? "" : cookie);
    int i = src.indexOf("; " + name + "=");
    if (i < 0) {
      return null;
    }
    int start = i + name.length() + 3;
    int j = src.indexOf(';', start);
    return j < 0 ? src.substring(start) : src.substring(start, j);
  }

  private static Map.Entry<String, String> h(String k, String v) {
    return new AbstractMap.SimpleEntry<>(k, v);
  }

  /** Whether the cookies camada sets carry Secure: the session and challenge cookies must agree. */
  private static boolean secure(Req req) {
    return req.https() || "https".equals(req.header("x-forwarded-proto"));
  }

  // ---- the adapter contract ----

  /**
   * The byte cap to read the body under, when camada itself may answer this request; null when the
   * adapter must not read the body.
   */
  public Integer wantsBody(String method, String path) {
    if (disabled() || !"POST".equals(method)) {
      return null;
    }
    if (path.equals(fpPath) && beaconEnabled()) {
      return Constants.FP_MAX;
    }
    if (path.equals(challengePath) && challengeOn) {
      return Constants.BODY_MAX;
    }
    return null;
  }

  /**
   * Never throws. {@code body} is the request body when wantsBody() asked for one, or null when the
   * adapter refused to read it (declared or actual size over the cap).
   */
  public Result handle(Req req, byte[] body) {
    try {
      return decide(req, body);
    } catch (RuntimeException | StackOverflowError err) {
      // A camada bug costs the join, never the request. StackOverflowError is an Error, but it is
      // the one a tenant's regex (java.util.regex recurses per group iteration) or a deeply nested
      // beacon body can raise on a request thread — Python's re and json fail open there.
      Guarded.logRateLimited(err);
      return Passed.INERT;
    }
  }

  protected Result decide(Req req, byte[] body) {
    if (disabled()) {
      return Passed.INERT;
    }
    long t0 = System.nanoTime();
    long ts0 = nowMs(); // ts is the request start, the moment dur counts from
    snap.ensureFresh();
    String ip = ip(req);

    // Enforce before anything else, beacon endpoints included — fail open while cold. The
    // custom rules read the user agent and the request headers (§D3).
    MatchResult v =
        snap.verdict(
            new MatchInput(
                ip, null, null, null, req.path(), req.header("user-agent"), req::header));
    if (v.block()) {
      List<Map.Entry<String, String>> headers = new ArrayList<>();
      headers.add(h("content-type", "text/plain"));
      headers.add(h("x-block-reason", v.reason() == null ? "" : v.reason()));
      headers.add(h("x-block-version", v.version() == null ? "" : v.version()));
      if (v.rule() != null) {
        // a custom rule blocked: name it, so the customer knows which row to edit
        headers.add(h("x-block-rule", v.rule()));
      }
      Map<String, Object> ev = event(req, UUID.randomUUID().toString(), null, false, ip);
      ev.put("st", 403); // blocked requests always ship: silent expiry makes blocks oscillate
      // the reason rides the event so the analyst counts SDK blocks, not the app's own 403s
      ev.put("blk", v.reason());
      if (v.rule() != null) {
        ev.put("rl", v.rule());
      }
      queue.push(ev);
      return new Answer(403, headers, "Forbidden".getBytes(StandardCharsets.UTF_8));
    }
    // `warn` passes the request and only marks its event (below, on finish); a skip passes
    // with nothing stamped at all — it is the absence of enforcement.

    // A challenge needs a resolved client IP: the nonce and the _cch cookie are bound to it,
    // so without one a single solve would mint a cookie every unidentified client could
    // present. No ip -> no challenge (fail open), the same stance ip rules take.
    String sid = cookieValue(req.header("cookie"), Constants.SESSION_COOKIE);
    if (challengeOn && ip != null && !ip.isEmpty()) {
      // The verify endpoint answers first: a challenged client must be able to reach it.
      if ("POST".equals(req.method()) && req.path().equals(challengePath)) {
        return verify(req, body, ip, sid);
      }
      if (v.challenge() && !challengePassed(req, ip)) {
        return serveChallenge(req, ip, sid);
      }
    }

    if (beaconEnabled()) {
      if ("GET".equals(req.method()) && req.path().equals(scriptPath)) {
        return new Answer(
            200,
            List.of(
                h("content-type", "application/javascript"),
                h("cache-control", "public, max-age=3600")),
            BeaconJs.BYTES);
      }
      if ("POST".equals(req.method()) && req.path().equals(fpPath)) {
        return relayBeacon(body, ip);
      }
    }

    String rid = UUID.randomUUID().toString();
    boolean newSession = sid == null || sid.isEmpty();
    String setCookie = null;
    if (newSession) {
      sid = UUID.randomUUID().toString();
      setCookie =
          Constants.SESSION_COOKIE
              + "="
              + sid
              + "; Path=/; Max-Age="
              + Constants.SESSION_MAX_AGE
              + "; HttpOnly; SameSite=Lax"
              + (secure(req) ? "; Secure" : "");
    }
    Context ctx = new Context(rid, sid, ip, req, this);

    RemoteConfig cfg = snap.config();
    boolean excluded = false;
    if (cfg != null) {
      for (String x : cfg.exclude()) {
        if (req.path().startsWith(x)) {
          excluded = true;
          break;
        }
      }
    }
    Double sample = cfg != null ? cfg.sample() : null;
    boolean sampled =
        ThreadLocalRandom.current().nextDouble()
            < (sample == null ? 1.0 : sample); // sampling, not crypto
    String warnRule = v.warn() ? v.rule() : null;
    boolean isExcluded = excluded;
    String finalSid = sid;

    IntConsumer onFinish =
        status -> {
          try {
            // serveChallenge() may have answered from inside the app, and it already shipped
            // the `blk: "challenge"` row — one request, one event.
            if (ctx.challenged || isExcluded || !sampled) {
              return;
            }
            Map<String, Object> ev = event(req, rid, finalSid, newSession, ip);
            ev.put("ts", ts0);
            ev.put("st", status);
            ev.put("dur", (System.nanoTime() - t0) / 1_000_000L);
            String route = ctx.route;
            if (route != null && !route.isEmpty()) {
              ev.put("rt", route);
            }
            if (warnRule != null) {
              ev.put("wrn", warnRule); // §D3: the warn rule that let this request through
            }
            queue.push(ev);
          } catch (RuntimeException | StackOverflowError err) {
            Guarded.logRateLimited(err);
          }
        };
    return new Passed(rid, setCookie, ctx, onFinish);
  }

  private Map<String, Object> event(
      Req req, String rid, String sid, boolean newSession, String ip) {
    RequestInfo info =
        new RequestInfo(
            req.method(),
            req.host(),
            req.path(),
            req.query(),
            req.headers(),
            ip,
            req.httpVersion());
    return Builder.build(info, Constants.TAP, rid, sid, newSession, null);
  }

  // ---- beacon ----

  /**
   * Answers 204, and queues the beacon as a {@code sig: 1} row with the trusted-proxy-resolved
   * client IP: it rides the next event batch. Junk bodies are dropped, never shipped.
   */
  private Answer relayBeacon(byte[] body, String ip) {
    if (body == null) {
      return new Answer(413, List.of(), new byte[0]);
    }
    Answer answer = new Answer(204, List.of(h("cache-control", "no-store")), new byte[0]);
    Map<String, Object> parsed;
    try {
      parsed = Json.asMap(Json.parse(new String(body, StandardCharsets.UTF_8)));
    } catch (IllegalArgumentException e) {
      return answer;
    }
    if (parsed == null) {
      return answer;
    }
    Map<String, Object> row =
        new LinkedHashMap<>(parsed); // spread first: ip and tap are the server's word
    row.put("sig", 1);
    row.put("ip", ip);
    row.put("tap", Constants.TAP);
    queue.push(row);
    return answer;
  }

  /** For HTML templates: the first-party beacon tag with the request's rid. */
  public String scriptTag(Context ctx) {
    if (disabled() || !beaconEnabled()) {
      return "";
    }
    String rid = ctx != null ? ctx.rid() : null;
    return "<script src=\"" + scriptPath + (rid != null ? "?r=" + rid : "") + "\" async></script>";
  }

  // ---- challenge ----

  private boolean challengePassed(Req req, String ip) {
    return kit.tokenValid(ip, nowMs(), cookieValue(req.header("cookie"), Format.CHALLENGE_COOKIE));
  }

  private Answer page(String ip, String to) {
    String html = Page.render(kit.nonce(ip, nowMs()), challengePath, to);
    return new Answer(
        403,
        List.of(
            h("content-type", "text/html; charset=utf-8"),
            h("cache-control", "no-store"),
            h("x-camada-challenge", "1")),
        html.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * 403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the {@code
   * blk: "challenge"} event — a served challenge is reported like a block (contract §D2).
   */
  private Answer serveChallenge(Req req, String ip, String sid) {
    String to = Format.safeReturnTo(req.path() + req.query());
    Answer answer;
    if (Format.wantsHtml(req.header("accept"), req.header("sec-fetch-dest"))) {
      answer = page(ip, to);
    } else {
      answer =
          new Answer(
              403,
              List.of(
                  h("content-type", "application/json"),
                  h("cache-control", "no-store"),
                  h("x-camada-challenge", "1")),
              "{\"error\":\"challenge_required\"}".getBytes(StandardCharsets.UTF_8));
    }
    try {
      Map<String, Object> ev = event(req, UUID.randomUUID().toString(), sid, false, ip);
      ev.put("st", 403);
      ev.put("blk", "challenge");
      queue.push(ev);
    } catch (RuntimeException | StackOverflowError err) {
      Guarded.logRateLimited(err); // the response is decided; telemetry must never undo that
    }
    return answer;
  }

  /**
   * POST from the challenge page: validate the nonce and the proof of work, set _cch, 302 back to
   * the (sanitised, same-site) original URL, and ship {@code { st: 200, ch: 1 }}.
   */
  private Answer verify(Req req, byte[] body, String ip, String sid) {
    if (body == null) {
      return new Answer(413, List.of(), new byte[0]);
    }
    Map<String, String> form = Format.parseFormBody(new String(body, StandardCharsets.UTF_8));
    String to = Format.safeReturnTo(form.get("to"));
    long now = nowMs();
    if (!kit.verify(ip, now, form.get("nonce"), form.get("solution"))) {
      return page(ip, to);
    }
    String cookie = Format.challengeCookie(kit.issue(ip, now), secure(req));
    Map<String, Object> ev = event(req, UUID.randomUUID().toString(), sid, false, ip);
    ev.put("st", 200);
    ev.put("ch", 1); // challenge passed (contract §A3 ingest field)
    queue.push(ev);
    return new Answer(
        302,
        List.of(h("location", to), h("set-cookie", cookie), h("cache-control", "no-store")),
        new byte[0]);
  }

  /**
   * Serve the challenge for this request on demand — for a route the app wants to gate itself. Null
   * when the client already holds a valid _cch (render your own page), or when the client cannot be
   * identified (fail open).
   */
  public Answer serveChallenge(Context ctx) {
    try {
      if (disabled() || ctx == null) {
        return null;
      }
      Req req = ctx.req;
      String ip = ctx.ip();
      if (req == null || ip == null || ip.isEmpty() || challengePassed(req, ip)) {
        return null;
      }
      ctx.challenged = true;
      return serveChallenge(req, ip, ctx.sid());
    } catch (RuntimeException | StackOverflowError err) {
      Guarded.logRateLimited(err);
      return null;
    }
  }

  // ---- app-context events ----

  /**
   * App-context outcome events (login failed, signup, ...). The identifier is HMAC-hashed
   * in-process; the raw value never reaches the queue. Never throws; a no-op without an engine.
   */
  public void track(Context ctx, String event, String user) {
    try {
      if (disabled()) {
        return;
      }
      String uid =
          user != null && !user.isEmpty() ? Redact.hashUserId(user, env.ingestToken()) : null;
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("tap", Constants.TAP);
      row.put("et", event);
      row.put("uid", uid);
      row.put("rid", ctx != null ? ctx.rid() : null);
      row.put("sid", ctx != null ? ctx.sid() : null);
      row.put("ip", ctx != null ? ctx.ip() : null);
      row.put("ts", nowMs());
      queue.push(row);
    } catch (RuntimeException | StackOverflowError err) {
      Guarded.logRateLimited(err);
    }
  }

  public void stop() {
    if (snap != null) {
      snap.stop();
    }
    if (queue != null) {
      queue.stop();
    }
  }

  // ---- servlet helpers: the request carries the context the filter stored ----

  /** The context the filter stored on this request, or null when it did not run. */
  public static Context contextOf(HttpServletRequest req) {
    Object ctx = req.getAttribute("camada");
    return ctx instanceof Context c ? c : null;
  }

  /**
   * For HTML templates: {@code <script src="/_cam/b.js?r=<rid>" async></script>}, or "" when off
   * (or when no engine exists yet: the helpers never build the default, see {@link #engineFor}).
   */
  public static String scriptTag(HttpServletRequest req) {
    Context ctx = contextOf(req);
    Camada eng = engineFor(ctx);
    return eng == null ? "" : eng.scriptTag(ctx);
  }

  /** {@code Camada.track(req, "login_failed", email)} from a handler; never throws. */
  public static void track(HttpServletRequest req, String event, String user) {
    Context ctx = contextOf(req);
    Camada eng = engineFor(ctx);
    if (eng != null) {
      eng.track(ctx, event, user);
    }
  }

  /**
   * Writes the proof-of-work page (or 403 JSON) for a route the app gates itself and returns true;
   * false once the browser holds a valid _cch, or when the client cannot be identified (fail open)
   * — render your own page then.
   */
  public static boolean serveChallenge(HttpServletRequest req, HttpServletResponse res)
      throws IOException {
    Context ctx = contextOf(req);
    Camada eng = engineFor(ctx);
    Answer a = eng == null ? null : eng.serveChallenge(ctx);
    if (a == null) {
      return false;
    }
    write(a, res);
    return true;
  }

  /** Writes an Answer to a servlet response: status, headers, content length, body. */
  public static void write(Answer a, HttpServletResponse res) throws IOException {
    res.setStatus(a.status());
    for (Map.Entry<String, String> h : a.headers()) {
      if (h.getKey().equalsIgnoreCase("content-type")) {
        res.setContentType(h.getValue());
      } else {
        res.addHeader(h.getKey(), h.getValue());
      }
    }
    res.setContentLength(a.body().length);
    res.getOutputStream().write(a.body());
    res.flushBuffer();
  }
}
