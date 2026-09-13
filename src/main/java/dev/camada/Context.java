package dev.camada;

/**
 * The per-request context the engine hands the app (the "camada" request attribute): the rid the
 * response carries, the session id, the resolved client ip, plus what the helpers need — the
 * request as the engine saw it and the engine that produced it. {@code challenged} records that
 * serveChallenge() answered from inside the app (one request, one event); {@code route} is the
 * matched route pattern the host learns at finish time.
 */
public final class Context {
  private final String rid;
  private final String sid;
  private final String ip;
  final Req req;
  final Camada engine;
  volatile boolean challenged;
  volatile String route;

  Context(String rid, String sid, String ip, Req req, Camada engine) {
    this.rid = rid;
    this.sid = sid;
    this.ip = ip;
    this.req = req;
    this.engine = engine;
  }

  public String rid() {
    return rid;
  }

  public String sid() {
    return sid;
  }

  public String ip() {
    return ip;
  }

  /** The matched route pattern, for a host that knows it at finish time (rides the event as rt). */
  public void route(String route) {
    this.route = route;
  }
}
