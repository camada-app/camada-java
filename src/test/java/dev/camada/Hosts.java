package dev.camada;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.camada.servlet.CamadaFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Drivers that run the SDK through the servlet host without a server: a MockHttpServletRequest /
 * MockHttpServletResponse pair through CamadaFilter and a FilterChain standing in for the app. The
 * engine suite proves the contract through it; host-specific behaviour lives in FilterTest.
 */
public final class Hosts {
  private Hosts() {}

  public static final Map<String, String> ENV =
      Map.of("CAMADA_KEY", "tok-test.snap-test", "CAMADA_INGEST_URL", "https://analyst.test");

  /** A peer no golden container lists (10.0.0.0/8 is blocked in all of them). */
  public static final String PEER = "172.16.0.9";

  /** What the host answered. */
  public record Reply(int status, List<Map.Entry<String, String>> headers, byte[] body) {
    public String header(String name) {
      for (Map.Entry<String, String> h : headers) {
        if (h.getKey().equalsIgnoreCase(name)) {
          return h.getValue();
        }
      }
      return null;
    }

    public List<String> headersNamed(String name) {
      List<String> out = new ArrayList<>();
      for (Map.Entry<String, String> h : headers) {
        if (h.getKey().equalsIgnoreCase(name)) {
          out.add(h.getValue());
        }
      }
      return out;
    }

    public String text() {
      return new String(body, StandardCharsets.UTF_8);
    }

    public static Reply of(int status, byte[] body, String... headerPairs) {
      List<Map.Entry<String, String>> h = new ArrayList<>();
      for (int i = 0; i < headerPairs.length; i += 2) {
        h.add(new AbstractMap.SimpleEntry<>(headerPairs[i], headerPairs[i + 1]));
      }
      return new Reply(status, h, body);
    }
  }

  /** One request to make; the defaults are a plain GET / from the unlisted peer over http. */
  public static final class Call {
    public final String method;
    public final String path;
    public final List<Map.Entry<String, String>> headers = new ArrayList<>();
    public byte[] body = new byte[0];
    public String peer = PEER;
    public boolean https;
    public Long contentLength; // override the declared length (null = actual)

    public Call(String method, String path) {
      this.method = method;
      this.path = path;
    }

    public Call header(String name, String value) {
      headers.add(new AbstractMap.SimpleEntry<>(name, value));
      return this;
    }

    public Call body(byte[] body) {
      this.body = body;
      return this;
    }

    public Call body(String body) {
      return body(body.getBytes(StandardCharsets.UTF_8));
    }

    public Call peer(String peer) {
      this.peer = peer;
      return this;
    }

    public Call https(boolean https) {
      this.https = https;
      return this;
    }

    public Call contentLength(long n) {
      this.contentLength = n;
      return this;
    }
  }

  /** A test app: sees the host's request and answers (status, headers, body). */
  @FunctionalInterface
  public interface AppHandler {
    Reply handle(HttpServletRequest req) throws Exception;
  }

  public static final AppHandler HELLO =
      req -> Reply.of(200, "hello".getBytes(), "content-type", "text/plain");

  public static Camada engineWith(FakeAnalyst a, Map<String, String> env, Options opts) {
    Map<String, String> merged = new HashMap<>(ENV);
    if (env != null) {
      merged.putAll(env);
    }
    return new Camada((opts == null ? new Options() : opts).env(merged).transport(a));
  }

  public static Camada engineWith(FakeAnalyst a) {
    return engineWith(a, null, null);
  }

  public static void loaded(Camada engine) {
    assertNotNull(engine.snapshot());
    assertTrue(engine.warmUp(2000), "snapshot never loaded");
  }

  public static void sleep(long ms) {
    try {
      Thread.sleep(ms);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /** A mock request whose declared content length can differ from its actual body. */
  static final class Request extends MockHttpServletRequest {
    Long declared;

    @Override
    public long getContentLengthLong() {
      return declared != null ? declared : super.getContentLengthLong();
    }

    @Override
    public int getContentLength() {
      return declared != null ? (int) (long) declared : super.getContentLength();
    }
  }

  /** The servlet host: CamadaFilter in front of a FilterChain that runs the handler. */
  public static final class ServletDriver {
    public final List<HttpServletRequest> seen = Collections.synchronizedList(new ArrayList<>());
    public final CamadaFilter filter;
    private final AppHandler handler;

    public ServletDriver(Camada engine, AppHandler handler) {
      this.filter = engine == null ? new CamadaFilter() : new CamadaFilter(engine);
      this.handler = handler;
    }

    public ServletDriver(Camada engine) {
      this(engine, HELLO);
    }

    public static MockHttpServletRequest request(Call c) {
      Request req = new Request();
      req.setMethod(c.method);
      String path = c.path;
      int q = path.indexOf('?');
      req.setRequestURI(q < 0 ? path : path.substring(0, q));
      req.setQueryString(q < 0 ? null : path.substring(q + 1));
      req.setProtocol("HTTP/1.1");
      req.setScheme(c.https ? "https" : "http");
      req.setSecure(c.https);
      req.setRemoteAddr(c.peer);
      req.setContent(c.body);
      req.declared = c.contentLength;
      boolean host = false;
      for (Map.Entry<String, String> h : c.headers) {
        req.addHeader(h.getKey(), h.getValue());
        host |= h.getKey().equalsIgnoreCase("host");
      }
      if (!host) {
        req.addHeader("host", "x.test");
      }
      return req;
    }

    public Reply call(Call c) throws IOException, ServletException {
      MockHttpServletRequest req = request(c);
      MockHttpServletResponse res = new MockHttpServletResponse();
      FilterChain chain =
          (rq, rs) -> {
            HttpServletRequest hrq = (HttpServletRequest) rq;
            HttpServletResponse hrs = (HttpServletResponse) rs;
            seen.add(hrq);
            Reply r;
            try {
              r = handler.handle(hrq);
            } catch (IOException | ServletException | RuntimeException e) {
              throw e;
            } catch (Exception e) {
              throw new ServletException(e);
            }
            hrs.setStatus(r.status());
            for (Map.Entry<String, String> h : r.headers()) {
              hrs.addHeader(h.getKey(), h.getValue());
            }
            hrs.getOutputStream().write(r.body());
            hrs.flushBuffer();
          };
      filter.doFilter(req, res, chain);
      return reply(res);
    }

    public static Reply reply(MockHttpServletResponse res) {
      List<Map.Entry<String, String>> headers = new ArrayList<>();
      for (String name : res.getHeaderNames()) {
        for (String v : res.getHeaders(name)) {
          headers.add(new AbstractMap.SimpleEntry<>(name.toLowerCase(java.util.Locale.ROOT), v));
        }
      }
      return new Reply(res.getStatus(), headers, res.getContentAsByteArray());
    }
  }
}
