package dev.camada;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import dev.camada.Transport.Response;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HttpTransportGzipTest {
  /** A body that cannot be decoded is no answer: status 0 and none of its headers (retry-after). */
  @Test
  void gzipDecodeFailureDropsHeaders() {
    Map<String, String> h = new HashMap<>();
    h.put("content-encoding", "gzip");
    h.put("retry-after", "30");
    Response r = HttpTransport.response(503, h, new byte[] {1, 2, 3, 4});
    assertEquals(0, r.status());
    assertNull(r.headers().get("retry-after"));
    assertEquals(0, r.body().length);
  }

  /**
   * A 304 carries Content-Encoding: gzip but no body: nothing to decode, status and headers stay.
   */
  @Test
  void emptyBodyIsNeverDecoded() {
    Map<String, String> h = new HashMap<>();
    h.put("content-encoding", "gzip");
    h.put("retry-after", "30");
    Response r = HttpTransport.response(304, h, new byte[0]);
    assertEquals(304, r.status());
    assertEquals("30", r.headers().get("retry-after"));
    assertEquals(0, r.body().length);
  }
}
