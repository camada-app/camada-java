package dev.camada;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * What an adapter hands the engine. Header names are lower-cased; the list keeps the order the host
 * gave. {@code path} carries no query; {@code query} has the leading '?' or is empty; {@code peer}
 * is the socket peer the host vouches for: null or empty means there is no peer (a unix-socket
 * listener), so a cidrs config walks X-Forwarded-For alone. {@code peerUnreadable} says the request
 * came over a socket whose peer could not be read: the client ip is then null (contract C6 v3),
 * never the X-Forwarded-For walk. The matched route pattern is not here: the host learns it at
 * finish time and sets it through the {@link Context}.
 */
public record Req(
    String method,
    String path,
    String query,
    String host,
    String httpVersion,
    String peer,
    boolean https,
    List<Map.Entry<String, String>> headers,
    boolean peerUnreadable) {

  /** A request whose peer was read (or that has none). */
  public Req(
      String method,
      String path,
      String query,
      String host,
      String httpVersion,
      String peer,
      boolean https,
      List<Map.Entry<String, String>> headers) {
    this(method, path, query, host, httpVersion, peer, https, headers, false);
  }

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
