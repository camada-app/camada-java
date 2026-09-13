package dev.camada.servlet;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

/**
 * The status the app settled on, read from the container's own response when the response is done —
 * setStatus, sendError, sendRedirect and reset all land there, and {@code startAsync()} with no
 * arguments hands the app that object rather than this wrapper, so it is the one source. A host
 * response that cannot say (getStatus() throwing) reads as 200: the event must never take the
 * request down.
 */
public final class StatusResponseWrapper extends HttpServletResponseWrapper {
  public StatusResponseWrapper(HttpServletResponse response) {
    super(response);
  }

  @Override
  public int getStatus() {
    try {
      return super.getStatus();
    } catch (RuntimeException e) {
      return SC_OK;
    }
  }
}
