package dev.camada.servlet;

import dev.camada.Answer;
import dev.camada.Camada;
import dev.camada.Guarded;
import dev.camada.Options;
import dev.camada.Passed;
import dev.camada.Req;
import dev.camada.Result;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The jakarta.servlet Filter: register it first (Spring Boot: a FilterRegistrationBean at
 * Ordered.HIGHEST_PRECEDENCE) so camada answers before routing. On a {@link Passed} it stamps x-rid
 * and the _sfp cookie BEFORE the chain runs, stores the {@link dev.camada.Context} as the "camada"
 * request attribute, observes the status through {@link StatusResponseWrapper}, and fires
 * onFinish(status) exactly once: after the chain returns, in the AsyncListener's onComplete when
 * the app went async, or with 500 when the chain throws (the exception propagates unchanged). Only
 * the original REQUEST dispatch is handled; ASYNC, ERROR, FORWARD and INCLUDE dispatches pass
 * straight through. Without an engine it wires the lazy default from the environment on the first
 * request.
 */
public final class CamadaFilter implements Filter {
  /**
   * The Spring MVC attribute naming the matched route pattern; read as a String, no Spring
   * dependency.
   */
  static final String ROUTE_ATTRIBUTE =
      "org.springframework.web.servlet.HandlerMapping.bestMatchingPattern";

  private final Camada engine;
  private final Options opts;

  /** The default engine, built from the environment on the first request. */
  public CamadaFilter() {
    this(null, null);
  }

  /** The default engine, built with these options on the first request. */
  public CamadaFilter(Options opts) {
    this(null, opts);
  }

  /** An engine the app built and hands in. */
  public CamadaFilter(Camada engine) {
    this(engine, null);
  }

  private CamadaFilter(Camada engine, Options opts) {
    this.engine = engine;
    this.opts = opts;
  }

  public Camada engine() {
    return engine != null ? engine : Camada.getDefault(opts);
  }

  @Override
  public void doFilter(ServletRequest sreq, ServletResponse sres, FilterChain chain)
      throws IOException, ServletException {
    if (!(sreq instanceof HttpServletRequest req)
        || !(sres instanceof HttpServletResponse res)
        || req.getDispatcherType() != DispatcherType.REQUEST) {
      chain.doFilter(sreq, sres);
      return;
    }
    Camada eng = engine();
    Req r;
    byte[] body = null;
    HttpServletRequest forApp = req;
    try {
      r = reqFrom(req);
      Integer cap = eng.wantsBody(r.method(), r.path());
      if (cap != null) {
        Read read = readBody(req, cap);
        body = read.body();
        forApp = read.request();
      }
    } catch (RuntimeException | IOException err) {
      Guarded.logRateLimited(err);
      chain.doFilter(forApp, res);
      return;
    }
    Result result = eng.handle(r, body);
    if (result instanceof Answer a) {
      Camada.write(a, res);
      return;
    }
    run(forApp, res, chain, (Passed) result);
  }

  private static void run(
      HttpServletRequest req, HttpServletResponse res, FilterChain chain, Passed p)
      throws IOException, ServletException {
    if (p.ctx() != null) {
      req.setAttribute("camada", p.ctx());
    }
    if (p.rid() != null) {
      res.setHeader("x-rid", p.rid());
    }
    if (p.setCookie() != null) {
      res.addHeader("Set-Cookie", p.setCookie());
    }
    if (p.onFinish() == null) {
      chain.doFilter(req, res);
      return;
    }
    StatusResponseWrapper wrapped = new StatusResponseWrapper(res);
    AtomicBoolean fired = new AtomicBoolean();
    Runnable finish =
        () -> {
          if (!fired.compareAndSet(false, true)) {
            return;
          }
          try {
            if (p.ctx() != null && req.getAttribute(ROUTE_ATTRIBUTE) instanceof String route) {
              p.ctx().route(route);
            }
          } catch (RuntimeException err) {
            Guarded.logRateLimited(err);
          }
          p.onFinish().accept(wrapped.getStatus());
        };
    try {
      chain.doFilter(req, wrapped);
    } catch (IOException | ServletException | RuntimeException | Error e) {
      if (fired.compareAndSet(false, true)) {
        p.onFinish().accept(500); // the app threw: the container will answer 500
      }
      throw e;
    }
    if (req.isAsyncStarted()) {
      req.getAsyncContext()
          .addListener(
              new AsyncListener() {
                @Override
                public void onComplete(AsyncEvent event) {
                  finish.run();
                }

                @Override
                public void onTimeout(AsyncEvent event) {}

                @Override
                public void onError(AsyncEvent event) {}

                @Override
                public void onStartAsync(AsyncEvent event) {
                  event
                      .getAsyncContext()
                      .addListener(this); // a re-started async cycle keeps the listener
                }
              });
      return;
    }
    finish.run();
  }

  /**
   * The engine's request from the servlet one: lower-cased header names in the container's order.
   */
  public static Req reqFrom(HttpServletRequest r) {
    List<Map.Entry<String, String>> headers = new ArrayList<>();
    Enumeration<String> names = r.getHeaderNames();
    if (names != null) {
      while (names.hasMoreElements()) {
        String name = names.nextElement();
        Enumeration<String> values = r.getHeaders(name);
        if (values == null) {
          continue;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        while (values.hasMoreElements()) {
          headers.add(new AbstractMap.SimpleEntry<>(lower, values.nextElement()));
        }
      }
    }
    String uri = r.getRequestURI();
    String query = r.getQueryString();
    String proto = r.getProtocol();
    String host = r.getHeader("host");
    return new Req(
        r.getMethod() == null ? "GET" : r.getMethod(),
        uri == null || uri.isEmpty() ? "/" : uri,
        query == null || query.isEmpty() ? "" : "?" + query,
        host != null && !host.isEmpty() ? host : r.getServerName(),
        proto != null && proto.startsWith("HTTP/") ? proto.substring(5) : null,
        r.getRemoteAddr(),
        r.isSecure(),
        headers,
        null);
  }

  /**
   * What readBody() hands back: the body under the cap (or null: refused), and the request the app
   * gets.
   */
  record Read(byte[] body, HttpServletRequest request) {}

  /**
   * At most {@code cap} bytes, or null when the declared or actual size exceeds it. Whatever was
   * read is put back (head, then the unread rest) so an app the request falls through to still sees
   * its whole body.
   */
  static Read readBody(HttpServletRequest req, int cap) throws IOException {
    if (req.getContentLengthLong() > cap) {
      return new Read(null, req); // refused before a byte is read
    }
    ServletInputStream in = req.getInputStream();
    byte[] buf = new byte[cap + 1];
    int n = 0;
    while (n < buf.length) {
      int got = in.read(buf, n, buf.length - n);
      if (got < 0) {
        break;
      }
      n += got;
    }
    HttpServletRequest replay = new ReplayRequestWrapper(req, buf, n, in);
    if (n > cap) {
      return new Read(null, replay); // over the cap: the prefix, then the unread rest
    }
    return new Read(Arrays.copyOf(buf, n), replay);
  }
}
