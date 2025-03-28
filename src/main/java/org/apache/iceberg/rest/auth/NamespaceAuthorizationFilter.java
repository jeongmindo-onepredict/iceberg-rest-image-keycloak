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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 네임스페이스 접근 권한을 검사하는 필터.
 * Keycloak 토큰에서 허용된 네임스페이스 목록을 확인하여 접근을 제어합니다.
 */
public class NamespaceAuthorizationFilter implements Filter {
    private static final Logger LOG = LoggerFactory.getLogger(NamespaceAuthorizationFilter.class);
    private static final Pattern NAMESPACE_PATTERN = Pattern.compile("/v1/namespaces/([^/]+)(?:/.*)?");
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        LOG.info("Initializing NamespaceAuthorizationFilter");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // 인증 바이패스 체크
        String bypassAuth = System.getenv("BYPASS_NAMESPACE_AUTH");
        if ("true".equalsIgnoreCase(bypassAuth)) {
            LOG.debug("Bypassing namespace authorization check");
            chain.doFilter(request, response);
            return;
        }
        
        // 요청 경로에서 네임스페이스 추출
        String path = httpRequest.getRequestURI();
        String namespace = extractNamespaceFromPath(path);
        
        if (namespace == null) {
            // 네임스페이스 관련 요청이 아니라면 그냥 통과
            chain.doFilter(request, response);
            return;
        }
        
        // Keycloak 인증 정보 확인
        KeycloakPrincipal<?> principal = (KeycloakPrincipal<?>) httpRequest.getUserPrincipal();
        
        if (principal == null) {
            LOG.warn("No Keycloak principal found in request for namespace {}", namespace);
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, 
                                 "Authentication required for namespace access");
            return;
        }
        
        RefreshableKeycloakSecurityContext securityContext = 
            (RefreshableKeycloakSecurityContext) principal.getKeycloakSecurityContext();
        AccessToken token = securityContext.getToken();
        
        // 네임스페이스 접근 권한 검사
        if (!hasNamespaceAccess(token, namespace)) {
            LOG.warn("Access denied to namespace {} for user {}", 
                     namespace, token.getPreferredUsername());
            httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, 
                                 "You don't have access to namespace: " + namespace);
            return;
        }
        
        LOG.debug("Access granted to namespace {} for user {}", 
                  namespace, token.getPreferredUsername());
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        LOG.info("Destroying NamespaceAuthorizationFilter");
    }
    
    /**
     * URI 경로에서 네임스페이스 이름을 추출합니다.
     */
    private String extractNamespaceFromPath(String path) {
        Matcher matcher = NAMESPACE_PATTERN.matcher(path);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }
    
    /**
     * 토큰의 정보를 기반으로 지정된 네임스페이스에 대한 접근 권한이 있는지 확인합니다.
     */
    private boolean hasNamespaceAccess(AccessToken token, String namespace) {
        // Admin 역할이 있으면 모든 네임스페이스에 접근 가능
        if (token.getRealmAccess() != null && 
            token.getRealmAccess().getRoles().contains("admin")) {
            LOG.debug("User has admin role, granting access to all namespaces");
            return true;
        }
        
        // 토큰에서 허용된 네임스페이스 목록 추출
        List<String> allowedNamespaces = extractAllowedNamespaces(token);
        
        // 네임스페이스 접근 권한 확인
        boolean hasAccess = allowedNamespaces.contains(namespace);
        LOG.debug("Namespace access check: namespace={}, allowedNamespaces={}, hasAccess={}", 
                  namespace, allowedNamespaces, hasAccess);
        
        return hasAccess;
    }
    
    /**
     * 토큰에서 허용된 네임스페이스 목록을 추출합니다.
     */
    @SuppressWarnings("unchecked")
    private List<String> extractAllowedNamespaces(AccessToken token) {
        Map<String, Object> otherClaims = token.getOtherClaims();
        if (otherClaims == null || !otherClaims.containsKey("iceberg-namespaces")) {
            return Collections.emptyList();
        }
        
        Object namespacesObj = otherClaims.get("iceberg-namespaces");
        
        if (namespacesObj instanceof List) {
            return (List<String>) namespacesObj;
        } else if (namespacesObj instanceof String) {
            String namespacesStr = (String) namespacesObj;
            if (namespacesStr.startsWith("[") && namespacesStr.endsWith("]")) {
                namespacesStr = namespacesStr.substring(1, namespacesStr.length() - 1);
            }
            
            List<String> namespaces = new ArrayList<>();
            for (String ns : namespacesStr.split(",")) {
                namespaces.add(ns.trim().replace("\"", ""));
            }
            
            return namespaces;
        }
        
        return Collections.emptyList();
    }
}