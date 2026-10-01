package dev.camada.snapshot;

import dev.camada.Config;
import dev.camada.Config.RemoteConfig;
import dev.camada.Constants;
import dev.camada.Guarded;
import dev.camada.HttpTransport;
import dev.camada.Json;
import dev.camada.Transport;
import dev.camada.Transport.Request;
import dev.camada.Transport.Response;
import dev.camada.snapshot.Matcher.MatchInput;
import dev.camada.snapshot.Matcher.MatchResult;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * SnapshotClient: the single-tenant port of the edge collector's snapshot lifecycle over the GET
 * /snapshot contract (ported from {@code @camada/core} src/snapshot/client.ts): 200 [u32 LE
 * meta-length][meta JSON][BLK container] + etag + x-camada-config; 304 nothing changed, config
 * header repeated (config refreshes every poll for free); 204 authenticated, no snapshot published
 * -> enforce nothing, fail open. Semantics ported exactly: single-in-flight load; loadedAt stamped
 * even on 204 (retry per poll cadence, not per request); any error keeps the previous snapshot;
 * cold = fail open. Timer mode runs one daemon scheduler thread (camada-snapshot) that re-schedules
 * itself at the current cadence; lazy mode submits a refresh to that same one-thread executor from
 * {@link #ensureFresh} when stale, so the request path never waits on the network.
 */
public final class Client {
  public enum Mode {
    TIMER,
    LAZY
  }

  /** Never loaded yet: fail open, mirrors the collector. */
  public static final MatchResult COLD =
      new MatchResult(false, false, false, false, null, null, "cold", null);

  private final String url;
  private final String token;
  private volatile Transport transport = new HttpTransport();
  private volatile double refreshS = Constants.DEFAULT_REFRESH_S;
  private volatile boolean pinned;
  private volatile long timeoutMs = 3000;
  private volatile Mode mode = Mode.TIMER;
  private volatile String sdk; // '<package>/<version>': sent as x-camada-sdk on every poll (SDK-03)
  private volatile int snapshotVersion = Constants.DEFAULT_SNAPSHOT_VERSION;

  private final AtomicReference<Matcher> matcher = new AtomicReference<>();
  private volatile RemoteConfig config;
  private volatile String etag;
  private volatile long loadedAtNanos; // 0 = never
  private final ReentrantLock loading = new ReentrantLock();
  private final ScheduledExecutorService exec =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread t = new Thread(r, "camada-snapshot");
            t.setDaemon(true);
            return t;
          });
  private volatile boolean stopped;
  private volatile boolean ticking;

  public Client(String url, String token) {
    this.url = url;
    this.token = token;
  }

  public Client transport(Transport transport) {
    this.transport = transport;
    return this;
  }

  /** Leave unset and the server's poll_seconds steers it; set it and it is pinned. */
  public Client refreshS(double seconds) {
    this.refreshS = seconds;
    this.pinned = true;
    return this;
  }

  public Client timeoutMs(long ms) {
    this.timeoutMs = ms;
    return this;
  }

  public Client mode(Mode mode) {
    this.mode = mode;
    return this;
  }

  public Client sdk(String sdk) {
    this.sdk = sdk;
    return this;
  }

  /** 5 asks for the custom rules too; 4 the sides only; 3 opts out of both. */
  public Client snapshotVersion(int v) {
    this.snapshotVersion = v;
    return this;
  }

  public Matcher matcher() {
    return matcher.get();
  }

  public RemoteConfig config() {
    return config;
  }

  public double refreshS() {
    return refreshS;
  }

  public Mode mode() {
    return mode;
  }

  public void start() {
    ensureFresh();
    if (mode != Mode.TIMER || ticking || stopped) {
      return;
    }
    ticking = true;
    schedule();
  }

  private void schedule() {
    try {
      exec.schedule(this::tick, (long) (refreshS * 1000), TimeUnit.MILLISECONDS);
    } catch (RejectedExecutionException e) {
      // stopped between the check and the schedule: the timer simply ends
    }
  }

  private void tick() {
    if (stopped) {
      return;
    }
    refreshIfStale();
    schedule();
  }

  public void stop() {
    stopped = true;
    exec.shutdownNow();
  }

  /**
   * 0.9 x refresh so a timer tick arriving at ~refresh-ε still refreshes; a full-interval
   * comparison makes every other tick a no-op (effective cadence 2x).
   */
  public boolean stale() {
    long at = loadedAtNanos;
    return at == 0 || (System.nanoTime() - at) > (long) (refreshS * 0.9 * 1_000_000_000L);
  }

  /** Kicks a refresh when stale; never blocks the request path, never throws. */
  public void ensureFresh() {
    if (stopped || !stale() || loading.isLocked()) {
      return;
    }
    try {
      exec.execute(this::refreshIfStale);
    } catch (RejectedExecutionException e) {
      // stopped: nothing to refresh
    }
  }

  /**
   * What the executor runs: two ensureFresh() calls can queue two tasks before either holds the
   * lock, so the task re-checks staleness — the second finds the first's load and does nothing, as
   * a manual refresh just before a timer tick makes that tick a no-op in the reference.
   */
  private void refreshIfStale() {
    if (stale()) {
      refresh();
    }
  }

  /**
   * One synchronous poll (single in-flight): what the timer calls, and what tests and warm-ups call
   * directly.
   */
  public void refresh() {
    if (!loading.tryLock()) {
      return;
    }
    try {
      load();
    } catch (RuntimeException err) { // a poll that can never succeed must not be silent, nor fatal
      Guarded.logRateLimited(err);
    } finally {
      loading.unlock();
    }
  }

  private void load() {
    Map<String, String> headers = new HashMap<>();
    headers.put("authorization", "Bearer " + token);
    headers.put("accept-encoding", "gzip");
    String tag = etag;
    if (tag != null) {
      headers.put("if-none-match", tag);
    }
    if (sdk != null) {
      headers.put("x-camada-sdk", sdk);
    }
    if (snapshotVersion > 3) {
      // a tenant without that container is answered with the next one down
      headers.put("x-camada-snapshot", String.valueOf(snapshotVersion));
    }
    Response res = transport.send(new Request("GET", url, headers, null, timeoutMs));
    if (res.status() != 200 && res.status() != 204 && res.status() != 304) {
      return; // 401/5xx/network: keep what we have
    }
    // loadedAt is stamped last (even when the body turns out corrupt): "not cold" is what warmUp()
    // and the request path read as "rules in place", so it must not be visible before the matcher
    // and config are.
    try {
      publish(res);
    } finally {
      loadedAtNanos = System.nanoTime();
    }
  }

  private void publish(Response res) {
    readConfig(res.headers().get("x-camada-config"));
    if (res.status() == 304) {
      return;
    }
    if (res.status() == 204) { // no snapshot published: enforce nothing
      matcher.set(null);
      etag = null;
      return;
    }
    byte[] body = res.body();
    if (body.length < 4) {
      throw new IllegalArgumentException("camada: truncated snapshot frame");
    }
    long metaLen =
        Integer.toUnsignedLong(ByteBuffer.wrap(body, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
    if (4 + metaLen > body.length) {
      throw new IllegalArgumentException("camada: truncated snapshot frame");
    }
    Map<String, Object> meta =
        Json.asMap(Json.parse(new String(body, 4, (int) metaLen, StandardCharsets.UTF_8)));
    if (meta == null) {
      throw new IllegalArgumentException("camada: snapshot meta is not an object");
    }
    // The server ships the v3, v4 and v5 bodies of one publish under the SAME meta.version and
    // different etags, so version alone cannot say "nothing changed".
    String newTag = res.headers().get("etag");
    Matcher current = matcher.get();
    if (current != null
        && String.valueOf(meta.get("version")).equals(current.snap.version())
        && newTag != null
        && newTag.equals(etag)) {
      return;
    }
    // Parser.parse throws on corrupt data -> caught by refresh(), previous kept
    ByteBuffer container =
        ByteBuffer.wrap(body, 4 + (int) metaLen, body.length - 4 - (int) metaLen);
    matcher.set(new Matcher(Parser.parse(container, meta)));
    etag = newTag;
  }

  private void readConfig(String raw) {
    if (raw == null || raw.isEmpty()) {
      return;
    }
    RemoteConfig cfg;
    try {
      cfg = Config.remoteConfig(Json.parse(raw));
    } catch (IllegalArgumentException e) {
      return; // keep the previous config
    }
    if (cfg == null) {
      return;
    }
    config = cfg;
    // the server steers the poll cadence per tenant (its cost lever) unless the client pinned one
    Double secs = cfg.pollSeconds();
    if (secs == null || pinned || !Double.isFinite(secs) || secs < 5 || secs == refreshS) {
      return;
    }
    refreshS = secs;
  }

  /** Cold (never loaded) and no-snapshot both fail open, mirroring the edge collector. */
  public MatchResult verdict(MatchInput i) {
    if (loadedAtNanos == 0) {
      return COLD;
    }
    Matcher m = matcher.get();
    return m == null ? MatchResult.NONE : m.match(i);
  }
}
