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

import java.util.HashMap;
import java.util.Map;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Keycloak 설정 리졸버 클래스.
 * 환경 변수에서 Keycloak 설정을 읽어 KeycloakDeployment 객체를 생성합니다.
 */
public class IcebergKeycloakConfigResolver implements KeycloakConfigResolver {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakConfigResolver.class);
    private KeycloakDeployment keycloakDeployment;

    @Override
    public KeycloakDeployment resolve(HttpFacade.Request request) {
        if (keycloakDeployment != null) {
            return keycloakDeployment;
        }

        LOG.info("Initializing Keycloak configuration from environment variables");
        
        String keycloakServerUrl = System.getenv("KEYCLOAK_SERVER_URL");
        String keycloakRealm = System.getenv("KEYCLOAK_REALM");
        String keycloakClientId = System.getenv("KEYCLOAK_CLIENT_ID");
        String keycloakClientSecret = System.getenv("KEYCLOAK_CLIENT_SECRET");
        
        if (keycloakServerUrl == null || keycloakRealm == null || 
            keycloakClientId == null || keycloakClientSecret == null) {
            LOG.error("Missing required Keycloak configuration. Please set KEYCLOAK_SERVER_URL, " +
                      "KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, and KEYCLOAK_CLIENT_SECRET environment variables.");
            throw new IllegalStateException("Missing required Keycloak configuration");
        }
        
        AdapterConfig config = new AdapterConfig();
        config.setRealm(keycloakRealm);
        config.setAuthServerUrl(keycloakServerUrl);
        config.setResource(keycloakClientId);
        
        Map<String, Object> credentials = new HashMap<>();
        credentials.put("secret", keycloakClientSecret);
        config.setCredentials(credentials);
        
        // REST 서비스이므로 bearer-only 모드 사용
        config.setBearerOnly(true);
        
        LOG.info("Keycloak configuration: realm={}, authServerUrl={}, resource={}", 
                 keycloakRealm, keycloakServerUrl, keycloakClientId);
        
        keycloakDeployment = KeycloakDeploymentBuilder.build(config);
        return keycloakDeployment;
    }
}