package dev.camada;

import java.util.Map;

/**
 * The one HTTP seam. The engine, the snapshot client and the event queue speak to the analyst
 * through a Transport, so tests inject an in-process fake and production uses {@link HttpTransport}
 * over java.net.http. A transport never throws: a network failure is a status-0 response, which
 * every caller treats as "keep what we have".
 */
@FunctionalInterface
public interface Transport {
  /** One outgoing request; {@code headers} are sent as given, {@code body} is null for a GET. */
  record Request(
      String method, String url, Map<String, String> headers, byte[] body, long timeoutMs) {}

  /** {@code status} is 0 when the request never got an answer; header names are lower-cased. */
  record Response(int status, Map<String, String> headers, byte[] body) {}

  Response send(Request req);
}
