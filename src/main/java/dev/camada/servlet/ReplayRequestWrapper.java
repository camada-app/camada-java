package dev.camada.servlet;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * The bytes camada already read (up to the cap + 1), then whatever is left in the stream the app
 * was owed: a beacon POST with the beacon off, or a verify POST from a client camada could not
 * identify, falls through to the app with its whole body. One stream or one reader per request, as
 * the servlet spec expects; non-blocking reads are not offered on a replayed body.
 */
public final class ReplayRequestWrapper extends HttpServletRequestWrapper {
  private final byte[] head;
  private final int headLen;
  private final ServletInputStream rest;
  private ServletInputStream stream;
  private BufferedReader reader;

  public ReplayRequestWrapper(
      HttpServletRequest request, byte[] head, int headLen, ServletInputStream rest) {
    super(request);
    this.head = head;
    this.headLen = headLen;
    this.rest = rest;
  }

  @Override
  public synchronized ServletInputStream getInputStream() {
    if (reader != null) {
      throw new IllegalStateException("getReader() has already been called for this request");
    }
    if (stream == null) {
      stream = new Replay();
    }
    return stream;
  }

  @Override
  public synchronized BufferedReader getReader() {
    if (stream != null) {
      throw new IllegalStateException("getInputStream() has already been called for this request");
    }
    if (reader == null) {
      String enc = getCharacterEncoding();
      Charset cs = StandardCharsets.ISO_8859_1;
      if (enc != null) {
        try {
          cs = Charset.forName(enc);
        } catch (RuntimeException e) {
          // an unsupported encoding reads as the servlet default
        }
      }
      reader = new BufferedReader(new InputStreamReader(new Replay(), cs));
    }
    return reader;
  }

  private final class Replay extends ServletInputStream {
    private int pos;

    @Override
    public int read() throws IOException {
      if (pos < headLen) {
        return head[pos++] & 0xFF;
      }
      return rest.read();
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      if (len == 0) {
        return 0;
      }
      if (pos < headLen) {
        int n = Math.min(len, headLen - pos);
        System.arraycopy(head, pos, b, off, n);
        pos += n;
        return n;
      }
      return rest.read(b, off, len);
    }

    @Override
    public boolean isFinished() {
      return pos >= headLen && rest.isFinished();
    }

    @Override
    public boolean isReady() {
      return true;
    }

    @Override
    public void setReadListener(ReadListener listener) {
      throw new IllegalStateException(
          "camada: non-blocking reads are not supported on a replayed body");
    }
  }
}
