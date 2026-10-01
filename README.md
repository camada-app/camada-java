# camada

camada for Java: enforces the tenant snapshot inline (your ordered custom rules, then allow,
block, challenge), serves a first-party proof-of-work challenge page and beacon, records the
outcomes your handlers know (`Camada.track(...)`), and ships wire events in batches off the
request path. One artifact, `dev.camada:camada`, with a plain `jakarta.servlet.Filter` that
Spring Boot, Tomcat, Jetty and Undertow all take as is. Fails open by design: a camada outage or
bug never 5xxes your app.

Not on Maven Central yet. From your project's folder: clone it next to the project, build it into
your local Maven repository, then add the dependency (as
[`camada-java-example`](https://github.com/camada-app/camada-java-example) does):

```
git clone https://github.com/camada-app/camada-java ../camada-java
mvn -q -f ../camada-java install -DskipTests
```

Publishing is one decision with the npm packages (SDK-G01). Java 17 or newer; the only runtime
dependency is the servlet API your container already provides.

## Quickstart

```xml
<!-- pom.xml -->
<dependency>
  <groupId>dev.camada</groupId>
  <artifactId>camada</artifactId>
  <version>0.1.2</version>
</dependency>
```

```java
// CamadaConfig.java, beside your @SpringBootApplication class
package com.example.demo;   // your application's package

import dev.camada.servlet.CamadaFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
class CamadaConfig {
  @Bean
  FilterRegistrationBean<CamadaFilter> camadaFilter() {
    var reg = new FilterRegistrationBean<>(new CamadaFilter());
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE);   // first, so camada answers before routing
    return reg;
  }
}
```

Any other servlet container:

```java
// CamadaListener.java: any servlet container (or declare the filter first in web.xml)
import dev.camada.servlet.CamadaFilter;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import jakarta.servlet.annotation.WebListener;

@WebListener
public class CamadaListener implements ServletContextListener {
  @Override
  public void contextInitialized(ServletContextEvent event) {
    event.getServletContext()
        .addFilter("camada", new CamadaFilter())
        .addMappingForUrlPatterns(null, false, "/*");   // false: ahead of the filters web.xml declares
  }
}
```

Set these as environment variables (the key is printed once when you create a project in the app):
export them in the shell that runs `./mvnw spring-boot:run` or the jar, or set them in your host's
settings. camada reads only the process environment: `application.properties` and a `.env` file
never reach it.

```
export CAMADA_KEY=<ingest_token>.<snap_token>
export CAMADA_INGEST_URL=http://localhost:8787   # dev only; defaults to production ingest
```

The filter shares one lazy engine (`Camada.getDefault()`) built from the environment on the first
request. That build starts the snapshot poll on a daemon thread and never blocks, so the request
that triggered it is answered cold: it passes (fail open), and so does anything else that arrives
before that first poll lands (a few hundred milliseconds against a local analyst; snapshot-size
and network bound). To enforce from request 1, warm the engine at startup by waiting for the boot
poll — `snapshot().refresh()` alone is not it, the boot poll already holds the single-in-flight
lock:

```java
// CamadaConfig.java: two more imports…
import dev.camada.Camada;
import org.springframework.boot.ApplicationRunner;

// …and one more @Bean in the class, run once the app has started
@Bean
ApplicationRunner camadaWarmUp() {
  // builds the engine (its boot poll is already running on its thread), then waits for that poll:
  // bounded, so an unreachable analyst leaves it cold, and the app still fails open
  return args -> Camada.getDefault().warmUp(5000);
}
```

(Elsewhere — a `ServletContextListener`, the end of `main()` — it is the same call: `Camada.getDefault().warmUp(5000);`.)

`warmUp(ms)` is bounded and never throws: false when the engine is inert, killed, or the analyst
did not answer in time. When the filter was handed `Options`, warm through `camadaFilter.engine()`
so the default is built with them.

Without `CAMADA_KEY` the engine is inert (one log line, no requests, no enforcement). An app that
reads its own config builds the engine itself and hands it in — or hands the filter the options
it should build the default engine with:

```java
// CamadaConfig.java, for an app that reads its own configuration: these imports too…
import dev.camada.Camada;
import dev.camada.Options;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;

// …and this filter bean in place of the one above
@Bean
FilterRegistrationBean<CamadaFilter> camadaFilter(
    @Value("${camada.key}") String key, @Value("${camada.ingest-url}") String ingest) {
  Camada engine = new Camada(new Options()
      .env(Map.of("CAMADA_KEY", key, "CAMADA_INGEST_URL", ingest))
      .challengePath("/api/__camada/challenge"));
  var reg = new FilterRegistrationBean<>(new CamadaFilter(engine));   // this engine, not the default
  // or new CamadaFilter(new Options().env(...)): the default engine, built with these options on the first request
  reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
  return reg;
}
```

The default is built once, by the first caller, with that caller's options. The static helpers
(`Camada.scriptTag`, `track`, `serveChallenge`) never build it: on a request the filter did not
run for, before the filter's first request, they are silent no-ops rather than a
`System.getenv()` default the filter would then be bound to.

## What it does per request

1. Keeps the snapshot fresh. A JVM is a long-lived process, so the default is a daemon poll thread
   (`camada-snapshot`) at the cadence your tenant config sets (`poll_seconds`, at least 5 s), with
   ETag/304 and gzip on the wire. `CAMADA_SERVERLESS=1` switches to a per-request staleness check
   that hands a refresh to the same daemon thread — the request path never waits on the network.
   Every poll and event batch carries `x-camada-sdk: @camada/java/<version>`, and polls ask for
   snapshot v5 (`x-camada-snapshot: 5`) — the container that carries your ordered custom rules.
2. Resolves the client from the socket peer (`getRemoteAddr()`), combined with `X-Forwarded-For`
   only under your tenant's trusted-proxy config (or `CAMADA_TRUSTED_PROXY` locally). A forwarded
   header on its own is never the ip: any caller can set it. Keep the container's own forwarded-
   header handling off (Spring Boot: `server.forward-headers-strategy=none`, the default) — a
   `RemoteIpValve` would rewrite the peer before camada judges the header.
3. Enforces before anything else, beacon endpoints included: your ordered custom rules first (first
   match wins; they read ip, path, user-agent and request headers), then allow → block → challenge.
   A block answers `403 Forbidden` with `x-block-reason`, `x-block-version` and, when a rule
   decided, `x-block-rule`; its event ships with `blk` (and `rl`). A `warn` rule passes and stamps
   `wrn`; a `skip` rule passes with nothing stamped. Cold (no snapshot yet) passes: fail open.
4. Challenge: a `challenge` verdict gets the self-contained proof-of-work page (or 403 JSON for a
   non-HTML request); `POST /__camada/challenge` verifies the solution, sets `_cch` (bound to the
   ip, one hour) and 302s back. A request whose ip cannot be resolved is never challenged.
5. Serves the beacon: `GET /_cam/b.js` (the `@camada/browser` build, vendored into the jar) and
   `POST /_cam/fp` (≤ 32 KB, relayed onto the event batch as a `sig: 1` row with the ip camada
   resolved). Both fall through to your app when the tenant switched the beacon off — with the
   body camada may already have read replayed to the app whole.
6. Runs your app with `x-rid` (the rid of the request's event row; never on a websocket handshake,
   which the container answers 101) and the `_sfp` session cookie on its response (stamped before
   the chain runs, so your handlers see them too), and when the response is done — after the chain
   returns, or in `AsyncListener.onComplete` when the app went async — ships one redacted event:
   method, host, path, scrubbed query, status, latency, header names/sizes/order, the auth scheme
   (never the credential), cookie count (never values), and the matched route pattern (`rt`) when
   Spring MVC set one. An exception in your app ships as `st: 500` and propagates unchanged.

The engine's seam is host-neutral — `wantsBody(method, path)`, `handle(Req, body)` returning an
`Answer` (camada wrote the response) or a `Passed` (run the app; `rid`, `setCookie`, the
`Context`, `onFinish(status)`) — so another host is one adapter away. `CamadaFilter` handles the
original `REQUEST` dispatch only; `ASYNC`, `ERROR`, `FORWARD` and `INCLUDE` dispatches pass through.

## Options

`new Camada(new Options()...)`; everything credential-shaped comes from the environment.

| option | default | meaning |
|---|---|---|
| `env(Map)` | `System.getenv()` | where `CAMADA_*` are read from |
| `transport(Transport)` | `java.net.http` | the HTTP seam that reaches the analyst (tests inject a fake) |
| `refreshS(double)` | server-steered | poll cadence; set, it is pinned |
| `challenge(boolean)` | `true` | serve the proof-of-work page for challenge verdicts (`CAMADA_CHALLENGE=0` too) |
| `challengePath(String)` | `/__camada/challenge` | where the page posts its solution |
| `snapshotVersion(int)` | `5` | 4 drops your custom rules; 3 the allow/challenge sides too |
| `scriptPath` / `fpPath` | `/_cam/b.js` / `/_cam/fp` | the beacon endpoints; keep them in one directory |

Env: `CAMADA_KEY` (or `CAMADA_TOKEN` + `CAMADA_SNAPSHOT_TOKEN`), `CAMADA_INGEST_URL`,
`CAMADA_SNAPSHOT_URL`, `CAMADA_TRUSTED_PROXY` (`none | vercel | hops:N | cidrs:a,b`),
`CAMADA_SERVERLESS=1`, `CAMADA_CHALLENGE=0`, and the kill switch `CAMADA_DISABLED=1` (checked per
request; set at boot, no threads start at all).

## The first-party beacon

```java
// PageController.java, beside CamadaConfig.java: the tag goes in the <head> of the pages you render
package com.example.demo;   // your application's package

import dev.camada.Camada;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class PageController {
  @GetMapping(value = "/", produces = "text/html")
  String home(HttpServletRequest request) {
    return "<html><head>" + Camada.scriptTag(request) + "</head><body>…</body></html>";
  }
}
```

The tag is `<script src="/_cam/b.js?r=<rid>" async>`, so the beacon joins the page view that
served it. Move both paths with `scriptPath` / `fpPath` when `/_cam/` is not yours; the script
derives the post path from its own URL, so the two must share a directory.

## App-context events

```java
// in a PageController handler, once your own sign-in check fails (email: the account it was for)
Camada.track(request, "login_failed", email);
```

The identifier is HMAC-hashed in-process with your ingest token; the raw value never reaches the
queue. `track()` never throws and is a no-op on a request the filter did not run for. The event
name is free-form; the analyst's app-context rules read this vocabulary:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a login attempt settled; pass the user so attempts per account can be counted |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a payment authorisation settled |
| `coupon_failed` | a promo/voucher code was rejected |

A route you gate yourself: `Camada.serveChallenge(request, response)` writes the page (or the 403
JSON) and returns true until the browser holds a valid `_cch`, then false — render your own page
then. The per-request `Context` (`rid`, `sid`, `ip`) is the `"camada"` request attribute.

## What this tap can see

`sdk-java` is an in-app tap: status, latency, session, the beacon's browser signals and your
outcomes, plus the wire's header order (`hord`) as the container hands it over. The analyst knows
what this tap can see and never scores the absence of ASN, country or a TLS fingerprint against a
request; ASN and country it resolves itself. Enforcement at this position covers ip, path,
user-agent and header conditions — ASN, country and TLS entries fail open in-app. `matches`
patterns are JS regexes read by `java.util.regex` (named groups, `[^]`, `\cX` and a bare `$` are
translated; `\d`/`\w`/`\b` stay ASCII); a spelling the engine still rejects — or a pattern it
cannot run against a request without overflowing the thread's stack — never matches here, while
it does at the edge.

## Deploying it

- Every JVM polls its own snapshot (about 5 MB resident) and flushes its own batches; the tenant's
  `poll_seconds` keeps the cadence honest across a fleet. Both threads are daemons: they never keep
  a JVM alive.
- Pending events drain at exit within half a second, from a JVM shutdown hook — which runs on
  SIGTERM as well as on a normal exit, an upgrade over the reference port's `atexit`: a container
  stopped by its orchestrator keeps its last batch. No signal handlers are installed — an app owns
  its own shutdown. A JVM does not fork, so there is no fork handling to speak of (the reference
  port's `register_at_fork` cases have no Java twin; the warm-up recipe above is tested in the
  engine suite instead).
- Serverless: `CAMADA_SERVERLESS=1`. A cold invocation fails open and catches up on the next one.

## Fail open

Every entry point runs inside the fail-open envelope: a dead ingest drops telemetry (logged at
most once a minute, on the `camada` `java.util.logging` logger, message only, never a stack
trace), a corrupt snapshot keeps the previous one, a bug in the package costs the request its
join, never its response. `CAMADA_DISABLED=1` bypasses everything.

## Not in this release

- A Spring Boot starter / auto-configuration: the filter is plain `jakarta.servlet`, and
  [`camada-java-example`](https://github.com/camada-app/camada-java-example) registers it by hand with a
  `FilterRegistrationBean`.
- Container-specific suites: the filter suite runs on Spring's mock servlet objects and the example
  on Tomcat; Jetty and Undertow take the same filter but are not exercised here.

## Development

```
mvn -q verify
```

`spotless:check` (google-java-format), `-Xlint:all -Werror`, then surefire. The suite reads the
golden snapshot fixtures from the `camada-core` sibling checkout (`CAMADA_FIXTURES_DIR` overrides)
and pins the vendored beacon to `camada-browser/dist/auto.global.js` (`CAMADA_BROWSER_DIST`
overrides; `npm run build` there first, then `scripts/sync-beacon.sh` after a beacon release).
Both fail by name when the checkout is missing rather than skipping. `mvn` may run on a newer JDK;
`<release>17</release>` keeps the build honest.

[`camada-java-example`](https://github.com/camada-app/camada-java-example) is the hand-test bench (Spring Boot on :3006), and
`node scripts/e2e-sdk-java.mjs` in `camada/edge-analyst` drives it against a seeded local analyst
over real HTTP, cold first request included.
