package dev.camada;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * What an adapter hands the engine. Header names are lower-cased; the list keeps the order the host
 * gave. {@code path} carries no query; {@code query} has the leading '?' or is empty; {@code peer}
 * is the socket peer the host vouches for. The matched route pattern is not here: the host learns
 * it at finish time and sets it through the {@link Context}.
 */
public record Req(
    String method,
    String path,
    String query,
    String host,
    String httpVersion,
    String peer,
    boolean https,
    List<Map.Entry<String, String>> headers) {

  public Req {
    query = query == null ? "" : query;
    host = host == null ? "" : host;
    headers = headers == null ? List.of() : List.copyOf(headers);
  }

  /**
   * A header the client repeated is joined the way node:http does it: cookies with '; ' (HTTP/2
   * clients split them into several fields; cookieValue() looks for '; name='), the rest with ', '.
   */
  public String header(String name) {
    List<String> vals = new ArrayList<>(1);
    for (Map.Entry<String, String> h : headers) {
      if (h.getKey().equals(name)) {
        vals.add(h.getValue());
      }
    }
    if (vals.isEmpty()) {
      return null;
    }
    return String.join(name.equals("cookie") ? "; " : ", ", vals);
  }
}
