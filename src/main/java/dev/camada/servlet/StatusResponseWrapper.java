package dev.camada.servlet;

import dev.camada.Camada;
import dev.camada.Context;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * The status the app settled on, read from the container's own response when the response is done —
 * setStatus, sendError, sendRedirect and reset all land there, and {@code startAsync()} with no
 * arguments hands the app that object rather than this wrapper, so it is the one source. A host
 * response that cannot say (getStatus() throwing) reads as 200: the event must never take the
 * request down.
 *
 * <p>It also stamps a signalled request (a non-HTML one that passed under a challenge) with {@code
 * x-camada-challenge: 1} and {@code no-store} on the CDN cache headers when the response commits:
 * on the first byte written or flushed, sendError, sendRedirect, flushBuffer, or the end of the
 * request for a response with no body. The flag is read then, because serveChallenge() can set it
 * from inside the app.
 */
public final class StatusResponseWrapper extends HttpServletResponseWrapper {
  private final Context ctx;

  public StatusResponseWrapper(HttpServletResponse response) {
    this(response, null);
  }

  public StatusResponseWrapper(HttpServletResponse response, Context ctx) {
    super(response);
    this.ctx = ctx;
  }

  @Override
  public int getStatus() {
    try {
      return super.getStatus();
    } catch (RuntimeException e) {
      return SC_OK;
    }
  }

  /** Replaces the app's cache headers and adds the signal, when the request is signalled. */
  void stamp() {
    if (ctx != null && ctx.signalled() && !isCommitted()) {
      for (String n : Camada.NO_STORE_HEADERS) {
        super.setHeader(n, "no-store"); // per client: replaces whatever the app set
      }
      super.setHeader("X-Camada-Challenge", "1");
    }
  }

  @Override
  public void sendError(int sc) throws IOException {
    stamp();
    super.sendError(sc);
  }

  @Override
  public void sendError(int sc, String msg) throws IOException {
    stamp();
    super.sendError(sc, msg);
  }

  @Override
  public void sendRedirect(String location) throws IOException {
    stamp();
    super.sendRedirect(location);
  }

  @Override
  public void flushBuffer() throws IOException {
    stamp();
    super.flushBuffer();
  }

  @Override
  public ServletOutputStream getOutputStream() throws IOException {
    ServletOutputStream out = super.getOutputStream();
    if (ctx == null) {
      return out;
    }
    return new ServletOutputStream() {
      @Override
      public boolean isReady() {
        return out.isReady();
      }

      @Override
      public void setWriteListener(WriteListener listener) {
        out.setWriteListener(listener);
      }

      @Override
      public void write(int b) throws IOException {
        stamp();
        out.write(b);
      }

      @Override
      public void write(byte[] b, int off, int len) throws IOException {
        stamp();
        out.write(b, off, len);
      }

      @Override
      public void flush() throws IOException {
        stamp();
        out.flush();
      }

      @Override
      public void close() throws IOException {
        stamp();
        out.close();
      }
    };
  }

  @Override
  public PrintWriter getWriter() throws IOException {
    PrintWriter out = super.getWriter();
    if (ctx == null) {
      return out;
    }
    // a PrintWriter around the container's own: checkError() reaches it, so a client disconnect
    // still shows to the app's SSE / long-poll loop
    return new PrintWriter(out) {
      @Override
      public void write(int c) {
        stamp();
        super.write(c);
      }

      @Override
      public void write(char[] c, int off, int len) {
        stamp();
        super.write(c, off, len);
      }

      @Override
      public void write(String str, int off, int len) {
        stamp();
        super.write(str, off, len);
      }

      @Override
      public void flush() {
        stamp();
        super.flush();
      }

      @Override
      public void close() {
        stamp();
        super.close();
      }
    };
  }
}
