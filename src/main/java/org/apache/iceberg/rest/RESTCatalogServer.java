/*
 * Copyright 2024 Tabular Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.iceberg.rest;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.hadoop.conf.Configuration;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.CatalogUtil;
import org.apache.iceberg.catalog.Catalog;
import org.apache.iceberg.rest.auth.AuthConfig;
import org.apache.iceberg.util.PropertyUtil;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RESTCatalogServer {
  private static final Logger LOG = LoggerFactory.getLogger(RESTCatalogServer.class);
  private static final String CATALOG_ENV_PREFIX = "CATALOG_";

  private RESTCatalogServer() {}

  record CatalogContext(Catalog catalog, Map<String,String> configuration) { }

  private static CatalogContext backendCatalog() throws IOException {
    // Translate environment variable to catalog properties
    Map<String, String> catalogProperties =
        System.getenv().entrySet().stream()
            .filter(e -> e.getKey().startsWith(CATALOG_ENV_PREFIX))
            .collect(
                Collectors.toMap(
                    e ->
                        e.getKey()
                            .replaceFirst(CATALOG_ENV_PREFIX, "")
                            .replaceAll("__", "-")
                            .replaceAll("_", ".")
                            .toLowerCase(Locale.ROOT),
                    Map.Entry::getValue,
                    (m1, m2) -> {
                      throw new IllegalArgumentException("Duplicate key: " + m1);
                    },
                    HashMap::new));

    // Fallback to a JDBCCatalog impl if one is not set
    catalogProperties.putIfAbsent(
        CatalogProperties.CATALOG_IMPL, "org.apache.iceberg.jdbc.JdbcCatalog");
    catalogProperties.putIfAbsent(
        CatalogProperties.URI, "jdbc:sqlite:file:/tmp/iceberg_rest_mode=memory");
    catalogProperties.putIfAbsent("jdbc.schema-version", "V1");

    // Configure a default location if one is not specified
    String warehouseLocation = catalogProperties.get(CatalogProperties.WAREHOUSE_LOCATION);

    if (warehouseLocation == null) {
      File tmp = java.nio.file.Files.createTempDirectory("iceberg_warehouse").toFile();
      tmp.deleteOnExit();
      warehouseLocation = tmp.toPath().resolve("iceberg_data").toFile().getAbsolutePath();
      catalogProperties.put(CatalogProperties.WAREHOUSE_LOCATION, warehouseLocation);

      LOG.info("No warehouse location set. Defaulting to temp location: {}", warehouseLocation);
    }

    LOG.info("Creating catalog with properties: {}", catalogProperties);
    return new CatalogContext(CatalogUtil.buildIcebergCatalog("rest_backend", catalogProperties, new Configuration()), catalogProperties);
  }

  public static void main(String[] args) throws Exception {
    LOG.info("Starting REST Catalog Server");
    
    // 인증 관련 설정 로깅
    logAuthConfig();
    
    CatalogContext catalogContext = backendCatalog();

    try (RESTCatalogAdapter adapter = new RESTServerCatalogAdapter(catalogContext)) {
      RESTCatalogServlet servlet = new RESTCatalogServlet(adapter);

      ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
      context.setContextPath("/");
      ServletHolder servletHolder = new ServletHolder(servlet);
      servletHolder.setInitParameter("javax.ws.rs.Application", "ServiceListPublic");
      context.addServlet(servletHolder, "/*");
      context.setVirtualHosts(null);
      context.setGzipHandler(new GzipHandler());
      
      // Keycloak 인증 및 권한 관리 설정 추가
      AuthConfig.configureAuth(context);

      int port = PropertyUtil.propertyAsInt(System.getenv(), "REST_PORT", 8181);
      LOG.info("Starting HTTP server on port {}", port);
      
      Server httpServer = new Server(port);
      httpServer.setHandler(context);

      httpServer.start();
      LOG.info("REST Catalog Server started successfully");
      
      httpServer.join();
    }
  }
  
  private static void logAuthConfig() {
    LOG.info("Authentication configuration:");
    LOG.info("  KEYCLOAK_ENABLED: {}", System.getenv("KEYCLOAK_ENABLED"));
    
    if ("true".equalsIgnoreCase(System.getenv("KEYCLOAK_ENABLED"))) {
      // 민감한 정보는 로그에 남기지 않음
      LOG.info("  KEYCLOAK_SERVER_URL: {}", System.getenv("KEYCLOAK_SERVER_URL"));
      LOG.info("  KEYCLOAK_REALM: {}", System.getenv("KEYCLOAK_REALM"));
      LOG.info("  KEYCLOAK_CLIENT_ID: {}", System.getenv("KEYCLOAK_CLIENT_ID"));
      LOG.info("  KEYCLOAK_CLIENT_SECRET: [REDACTED]");
      LOG.info("  BYPASS_NAMESPACE_AUTH: {}", System.getenv("BYPASS_NAMESPACE_AUTH"));
    }
  }
}