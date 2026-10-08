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
}
