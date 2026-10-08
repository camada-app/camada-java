package dev.camada;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;

/**
 * The production transport: {@link HttpClient} with a 2 s connect timeout and the request's own
 * timeout, gzip-aware (GET /snapshot ships ~5 MB that gzips to a few KB), and it never throws — a
 * network failure, a malformed URL or a body that cannot be read is a status-0 response.
 */
public final class HttpTransport implements Transport {
  private final HttpClient client;

  public HttpTransport() {
    this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build());
  }

  public HttpTransport(HttpClient client) {
    this.client = client;
  }

  @Override
  public Response send(Request req) {
    try {
      HttpRequest.Builder b =
          HttpRequest.newBuilder(URI.create(req.url()))
              .timeout(Duration.ofMillis(Math.max(1, req.timeoutMs())));
      for (Map.Entry<String, String> h : req.headers().entrySet()) {
        b.header(h.getKey(), h.getValue());
      }
      b.method(
          req.method(),
          req.body() == null
              ? HttpRequest.BodyPublishers.noBody()
              : HttpRequest.BodyPublishers.ofByteArray(req.body()));
      HttpResponse<byte[]> res = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
      Map<String, String> headers = new HashMap<>();
      for (Map.Entry<String, List<String>> e : res.headers().map().entrySet()) {
        if (!e.getValue().isEmpty()) {
          headers.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue().get(0));
        }
      }
      return response(res.statusCode(), headers, res.body());
    } catch (IOException | RuntimeException e) {
      return new Response(0, Map.of(), new byte[0]);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return new Response(0, Map.of(), new byte[0]);
    }
  }

  static Response response(int status, Map<String, String> lower, byte[] body) {
    if (body.length > 0 && "gzip".equalsIgnoreCase(lower.getOrDefault("content-encoding", ""))) {
      try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(body))) {
        body = gz.readAllBytes();
      } catch (IOException | RuntimeException e) {
        return new Response(
            0,
            Map.of(),
            new byte[0]); // no answer at all: its headers (retry-after) are not passed on
      }
      lower.remove("content-encoding");
    }
    return new Response(status, lower, body);
  }
}
