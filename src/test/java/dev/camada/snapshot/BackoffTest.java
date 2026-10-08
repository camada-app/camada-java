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
}
