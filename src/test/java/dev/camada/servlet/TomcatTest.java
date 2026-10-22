package dev.camada.servlet;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.camada.Camada;
import dev.camada.FakeAnalyst;
import dev.camada.Hosts;
import dev.camada.challenge.Page;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.util.List;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.junit.jupiter.api.Test;

/**
 * camada-all-y38o RB-2: what only a real container shows. Tomcat 10.1 (Spring Boot 3's default)
 * treats setHeader(name, null) as a no-op, so the report-only policy an app set before the
 * challenge page has to be overwritten, not removed.
 */
class TomcatTest {
  @Test
  void neitherAppPolicyReachesTheWireOnTomcat() throws Exception {
    FakeAnalyst analyst = new FakeAnalyst();
    Camada engine = Hosts.engineWith(analyst);
    Hosts.loaded(engine);
    Tomcat tomcat = new Tomcat();
    tomcat.setPort(0);
    tomcat.setBaseDir(Files.createTempDirectory("camada-tomcat").toString());
    tomcat.getConnector();
    Context ctx = tomcat.addContext("", null);
    FilterDef def = new FilterDef();
    def.setFilterName("camada");
    def.setFilter(new CamadaFilter(engine));
    ctx.addFilterDef(def);
    FilterMap map = new FilterMap();
    map.setFilterName("camada");
    map.addURLPatternDecoded("/*");
    ctx.addFilterMap(map);
    Tomcat.addServlet(
        ctx,
        "app",
        new HttpServlet() {
          private static final long serialVersionUID = 1L;

          @Override
          protected void doGet(HttpServletRequest q, HttpServletResponse r) throws IOException {
            r.setHeader("Content-Security-Policy", "default-src 'self'");
            r.addHeader("Content-Security-Policy", "script-src 'none'");
            r.setHeader("Content-Security-Policy-Report-Only", "script-src 'none'");
            Camada.serveChallenge(q, r);
          }
        });
    ctx.addServletMappingDecoded("/", "app");
    tomcat.start();
    try {
      int port = tomcat.getConnector().getLocalPort();
      HttpResponse<String> res =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/export"))
                      .header("accept", "text/html")
                      .header("sec-fetch-dest", "document")
                      .build(),
                  HttpResponse.BodyHandlers.ofString());
      assertEquals(403, res.statusCode());
      assertEquals(List.of(Page.csp()), res.headers().allValues("content-security-policy"));
      // overwritten with the page's own policy: removing it is a no-op on Tomcat 10.1
      assertEquals(
          List.of(Page.csp()), res.headers().allValues("content-security-policy-report-only"));
    } finally {
      tomcat.stop();
      tomcat.destroy();
      engine.stop();
    }
  }

  /** A signalled response must carry both headers to a real client, flushed early or large. */
  @Test
  void signalledResponsesCarryBothHeadersOnTomcat() throws Exception {
    FakeAnalyst analyst = new FakeAnalyst();
    Camada engine = Hosts.engineWith(analyst);
    Hosts.loaded(engine);
    Tomcat tomcat = new Tomcat();
    tomcat.setPort(0);
    tomcat.setBaseDir(Files.createTempDirectory("camada-tomcat").toString());
    tomcat.getConnector();
    Context ctx = tomcat.addContext("", null);
    FilterDef def = new FilterDef();
    def.setFilterName("camada");
    def.setFilter(new CamadaFilter(engine));
    ctx.addFilterDef(def);
    FilterMap map = new FilterMap();
    map.setFilterName("camada");
    map.addURLPatternDecoded("/*");
    ctx.addFilterMap(map);
    Tomcat.addServlet(
        ctx,
        "app",
        new HttpServlet() {
          private static final long serialVersionUID = 1L;

          @Override
          protected void doGet(HttpServletRequest q, HttpServletResponse r) throws IOException {
            Camada.serveChallenge(q, r);
            r.setHeader("Cache-Control", "public");
            if (q.getRequestURI().equals("/big")) {
              r.getWriter().write("x".repeat(20000)); // past the 8 KB buffer: commits mid-write
            } else {
              r.getWriter().write("hi");
              r.flushBuffer();
              r.getWriter().write("more");
            }
          }
        });
    ctx.addServletMappingDecoded("/", "app");
    tomcat.start();
    try {
      int port = tomcat.getConnector().getLocalPort();
      for (String path : List.of("/big", "/flush")) {
        HttpResponse<String> res =
            HttpClient.newHttpClient()
                .send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                        .header("accept", "application/json")
                        .build(),
                    HttpResponse.BodyHandlers.ofString());
        assertEquals(200, res.statusCode(), path);
        assertEquals("1", res.headers().firstValue("x-camada-challenge").orElse(null), path);
        assertEquals("no-store", res.headers().firstValue("cache-control").orElse(null), path);
      }
    } finally {
      tomcat.stop();
      tomcat.destroy();
      engine.stop();
    }
  }
}
