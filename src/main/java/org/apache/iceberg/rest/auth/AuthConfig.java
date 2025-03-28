/*
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

package org.apache.iceberg.rest.auth;

import java.util.EnumSet;
import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 인증 및 권한 관리를 위한 설정 클래스.
 * Keycloak 인증 및 네임스페이스 권한 관리를 위한 필터를 설정합니다.
 */
public class AuthConfig {
    private static final Logger LOG = LoggerFactory.getLogger(AuthConfig.class);

    private AuthConfig() {
        // 유틸리티 클래스이므로 인스턴스화 방지
    }

    /**
     * 인증 및 권한 관리 필터를 설정합니다.
     *
     * @param context Servlet 컨텍스트 핸들러
     */
    public static void configureAuth(ServletContextHandler context) {
        String keycloakEnabled = System.getenv("KEYCLOAK_ENABLED");
        
        if (!"true".equalsIgnoreCase(keycloakEnabled)) {
            LOG.info("Keycloak authentication is disabled. Set KEYCLOAK_ENABLED=true to enable.");
            return;
        }
        
        LOG.info("Configuring Keycloak authentication and authorization");
        
        try {
            // Keycloak 인증 필터 추가
            configureKeycloakFilter(context);
            
            // 네임스페이스 권한 관리 필터 추가
            configureNamespaceAuthFilter(context);
            
            LOG.info("Successfully configured authentication and authorization filters");
        } catch (Exception e) {
            LOG.error("Failed to configure authentication: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to configure authentication", e);
        }
    }
    
    /**
     * Keycloak 인증 필터를 설정합니다.
     */
    private static void configureKeycloakFilter(ServletContextHandler context) {
        // Keycloak OIDC 필터 등록
        FilterHolder keycloakFilter = new FilterHolder(KeycloakOIDCFilter.class);
        keycloakFilter.setName("keycloak-filter");
        keycloakFilter.setInitParameter("keycloak.config.resolver", 
                                       "org.apache.iceberg.rest.auth.IcebergKeycloakConfigResolver");
        
        // 모든 요청에 인증 필터 적용
        context.addFilter(keycloakFilter, "/*", EnumSet.of(DispatcherType.REQUEST));
        LOG.info("Registered Keycloak authentication filter");
    }
    
    /**
     * 네임스페이스 권한 관리 필터를 설정합니다.
     */
    private static void configureNamespaceAuthFilter(ServletContextHandler context) {
        // 네임스페이스 권한 관리 필터 등록
        FilterHolder namespaceFilter = new FilterHolder(NamespaceAuthorizationFilter.class);
        namespaceFilter.setName("namespace-auth-filter");
        
        // 네임스페이스 관련 경로에만 권한 필터 적용
        context.addFilter(namespaceFilter, "/v1/namespaces/*", EnumSet.of(DispatcherType.REQUEST));
        LOG.info("Registered namespace authorization filter for path: /v1/namespaces/*");
    }
    
    /**
     * 환경 변수에서 불리언 값을 읽습니다.
     */
    public static boolean getBooleanEnv(String name, boolean defaultValue) {
        String value = System.getenv(name);
        if (value == null || value.trim().isEmpty()) {
            return defaultValue;
        }
        return "true".equalsIgnoreCase(value.trim());
    }
}