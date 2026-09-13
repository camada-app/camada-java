package dev.camada;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * What an adapter hands the engine. Header names are lower-cased; the list keeps the order the host
 * gave. {@code path} carries no query; {@code query} has the leading '?' or is empty; {@code peer}
 * is the socket peer the host vouches for; {@code route} is the matched route pattern when the host
 * knows it at request time (the servlet filter learns it at finish, through the Context).
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
    String route) {

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
