package dev.camada;

import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

/**
 * An in-process transport standing in for the analyst Worker (GET /snapshot, POST /e): the Java
 * twin of camada-python's tests/fake_analyst.py and camada-node/test/harness.ts fakeAnalyst().
 */
public final class FakeAnalyst implements Transport {
  public static final String BLOCKED_IP = "203.0.113.66"; // an ip4 entry in v3-basic and v4-basic
  public static final String CHALLENGED_IP = "192.0.2.20"; // a challenge-only ip4 entry in v4-basic
  public static final String ALLOWED_IP = "10.0.0.7"; // allow-listed inside the blocked 10.0.0.0/8
  // v5-rules only (§D3): the ordered custom rules the golden container carries.
  public static final String RULE_BLOCKED_IP =
      "198.51.100.7"; // builtin:block, a manual-block entry
  public static final String SKIP_PATH = "/healthz"; // cr_00000000000a, skip — beats every side
  public static final String RULE_BLOCKED_PATH = "/api/v2/dump"; // cr_00000000000c, block by regex
  public static final String WARN_UA = "Scrapy/2.11 (+https://scrapy.org)"; // cr_00000000000e, warn
  public static final String BLOCKED_UA = "curl/8.4.0"; // cr_00000000000f, block
  public static final String BLOCKED_HEADER = "x-api-key"; // cr_000000000019, `header is` -> block
  public static final String BLOCKED_HEADER_VALUE = "leaked-key-1";

  static final Map<String, String> META_FILES =
      Map.of(
          "v3",
          "blk3/v3-basic.meta.json",
          "v4",
          "blk3/v4-basic.meta.json",
          "v5",
          "blk5/v5-rules.meta.json");
  static final Map<String, String> BIN_FILES =
      Map.of("v3", "blk3/v3-basic.bin", "v4", "blk3/v4-basic.bin", "v5", "blk5/v5-rules.bin");

  public final List<List<Map<String, Object>>> events =
      Collections.synchronizedList(new ArrayList<>()); // batches POSTed to /e
  public final List<String> sdkHeaders =
      Collections.synchronizedList(new ArrayList<>()); // x-camada-sdk on /snapshot and /e
  public final List<String> snapshotVersions =
      Collections.synchronizedList(new ArrayList<>()); // x-camada-snapshot on /snapshot
  public final List<Request> snapshotRequests = Collections.synchronizedList(new ArrayList<>());
  public final Map<String, Object> config = Collections.synchronizedMap(new LinkedHashMap<>());
  public volatile boolean snapshotDown;
  public volatile boolean ingestDown;
  public volatile Integer snapshotStatus; // force a status (204, 304, 401, 500)
  public volatile String container = "v3"; // v3 | v4 | v5
  public final Map<String, Object> metaExtra =
      Collections.synchronizedMap(new LinkedHashMap<>()); // laid over the fixture's meta

  public FakeAnalyst() {
    config.put("tenant", "acme");
    config.put("beacon", true);
    config.put("sample", 1L);
    config.put("exclude", List.of());
    config.put("trusted_proxy", Map.of("mode", "none"));
    config.put("poll_seconds", 30L);
  }

  public Map<String, Object> meta() {
    Map<String, Object> m = new LinkedHashMap<>(Fixtures.readMeta(META_FILES.get(container)));
    synchronized (metaExtra) {
      m.putAll(metaExtra);
    }
    return m;
  }

  public byte[] binary() {
    return Fixtures.readBin(BIN_FILES.get(container));
  }

  public String etag() {
    String suffix = Map.of("v3", "", "v4", "-v4", "v5", "-v5").get(container);
    return "\"" + meta().get("version") + suffix + "\"";
  }

  /** The GET /snapshot frame: [u32 LE meta length][meta JSON][BLK container]. */
  public static byte[] frame(Map<String, Object> meta, byte[] body) {
    byte[] m = Json.stringify(meta).getBytes(StandardCharsets.UTF_8);
    ByteBuffer b = ByteBuffer.allocate(4 + m.length + body.length).order(ByteOrder.LITTLE_ENDIAN);
    b.putInt(m.length).put(m).put(body);
    return b.array();
  }

  public static byte[] gzipBytes(byte[] raw) {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
        gz.write(raw);
      }
      return out.toByteArray();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public Response send(Request req) {
    if (req.url().endsWith("/snapshot") || req.url().endsWith("/e")) {
      sdkHeaders.add(req.headers().getOrDefault("x-camada-sdk", ""));
    }
    if (req.url().endsWith("/snapshot")) {
      snapshotRequests.add(req);
      snapshotVersions.add(req.headers().getOrDefault("x-camada-snapshot", ""));
      if (snapshotDown) {
        return new Response(0, Map.of(), new byte[0]);
      }
      Map<String, String> headers = new HashMap<>();
      synchronized (config) {
        headers.put("x-camada-config", Json.stringify(config));
      }
      headers.put("cache-control", "private, no-store");
      if (snapshotStatus != null) {
        return new Response(snapshotStatus, headers, new byte[0]);
      }
      if (etag().equals(req.headers().get("if-none-match"))) {
        return new Response(304, headers, new byte[0]);
      }
      byte[] body = frame(meta(), binary());
      headers.put("etag", etag());
      return new Response(200, headers, body);
    }
    if (ingestDown) {
      return new Response(0, Map.of(), new byte[0]);
    }
    if (req.url().endsWith("/e")) {
      List<Map<String, Object>> batch = new ArrayList<>();
      Object parsed =
          Json.parse(req.body() == null ? "[]" : new String(req.body(), StandardCharsets.UTF_8));
      for (Object o : (List<?>) parsed) {
        batch.add(Json.asMap(o));
      }
      events.add(batch);
      return new Response(202, Map.of(), new byte[0]);
    }
    fail("unmocked request: " + req.url());
    return null;
  }

  public List<Map<String, Object>> allEvents() {
    List<Map<String, Object>> out = new ArrayList<>();
    synchronized (events) {
      for (List<Map<String, Object>> batch : events) {
        out.addAll(batch);
      }
    }
    return out;
  }
}
