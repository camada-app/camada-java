package dev.camada;

import java.util.List;
import java.util.Map;

/** camada answered the request; the adapter writes exactly this. */
public record Answer(int status, List<Map.Entry<String, String>> headers, byte[] body)
    implements Result {
  public Answer {
    headers = headers == null ? List.of() : List.copyOf(headers);
    body = body == null ? new byte[0] : body;
  }

  public String header(String name) {
    for (Map.Entry<String, String> h : headers) {
      if (h.getKey().equalsIgnoreCase(name)) {
        return h.getValue();
      }
    }
    return null;
  }
}
