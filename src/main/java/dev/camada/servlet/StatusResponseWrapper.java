package dev.camada.servlet;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;

/**
 * Observes the status the app settles on, whichever way it sets it — setStatus, sendError,
 * sendRedirect, reset — so the filter can ship it in the event when the response is done. Thin:
 * every call still reaches the container's response, and {@link #getStatus} prefers what the
 * container's own response reports: {@code startAsync()} with no arguments hands the app that
 * object, not this wrapper, so a status set there must still reach the event.
 */
public final class StatusResponseWrapper extends HttpServletResponseWrapper {
  private volatile int status = SC_OK;

  public StatusResponseWrapper(HttpServletResponse response) {
    super(response);
  }

  @Override
  public void setStatus(int sc) {
    status = sc;
    super.setStatus(sc);
  }

  @Override
  public void sendError(int sc) throws IOException {
    status = sc;
    super.sendError(sc);
  }

  @Override
  public void sendError(int sc, String msg) throws IOException {
    status = sc;
    super.sendError(sc, msg);
  }

  @Override
  public void sendRedirect(String location) throws IOException {
    status = SC_FOUND;
    super.sendRedirect(location);
  }

  @Override
  public void reset() {
    status = SC_OK;
    super.reset();
  }

  @Override
  public int getStatus() {
    int underlying;
    try {
      underlying = super.getStatus();
    } catch (RuntimeException e) {
      underlying = 0; // a host response that cannot say: what passed through here
    }
    return underlying > 0 ? underlying : status;
  }
}
