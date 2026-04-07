package gajeman.jagalchi.jagalchiserver.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * WebSocket 핸드쉐이크 전용 필터
 * - Upgrade: websocket 요청에 대해 Authorization 헤더를 파싱하여
 *   X-User-ID, X-User-Role, X-Permissions, X-Roadmap-ID를 주입
 */
@Slf4j
@Component
public class WebSocketHandshakeFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final String HEADER_USER_ID = "X-User-ID";
    private static final String HEADER_USER_ROLE = "X-User-Role";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // Only act on WebSocket upgrade requests
        String upgrade = request.getHeaders().getFirst(HttpHeaders.UPGRADE);
        if (upgrade == null || !"websocket".equalsIgnoreCase(upgrade)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HEADER_AUTHORIZATION);
        String token = null;

        if (StringUtils.hasText(authHeader) && authHeader.startsWith(TOKEN_PREFIX)) {
            token = authHeader.substring(TOKEN_PREFIX.length());
        } else {
            // Try query param fallback (for SockJS / browsers where custom headers are not available)
            String tokenParam = request.getQueryParams().getFirst("access_token");
            if (StringUtils.hasText(tokenParam)) {
                token = tokenParam;
                log.debug("Found access_token query parameter for WebSocket handshake");
            }
        }

        if (!StringUtils.hasText(token)) {
            // No authorization token — let other layers decide (may be guest connect)
            log.debug("WebSocket handshake without Authorization or access_token, proceeding without injection");
            return chain.filter(exchange);
        }

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String tokenType = claims.get("type", String.class);
            if (!"ACCESS_TOKEN".equals(tokenType)) {
                log.warn("WebSocket handshake invalid token type: {}", tokenType);
                return onError(exchange, "INVALID_TOKEN", "Invalid token type", HttpStatus.UNAUTHORIZED);
            }

            Long userId = claims.get("id", Long.class);
            String role = claims.get("role", String.class);
            if (userId == null || role == null) {
                return onError(exchange, "INVALID_TOKEN", "Invalid token claims", HttpStatus.UNAUTHORIZED);
            }

            String mappedRole = switch (role.toUpperCase()) {
                case "STUDENT" -> "USER";
                case "TEACHER", "ADMIN" -> "ADMIN";
                default -> "USER";
            };

            String permissions = switch (mappedRole.toUpperCase()) {
                case "ADMIN" -> "ALL";
                case "USER" -> "READ,WRITE";
                default -> "READ";
            };

            // Try to extract roadmapId from query param or path
            String path = request.getURI().getPath();
            String roadmapId = request.getQueryParams().getFirst("roadmapId");
            if (!StringUtils.hasText(roadmapId)) {
                String[] segments = path.split("/");
                String last = segments.length > 0 ? segments[segments.length - 1] : "";
                if (last.matches("\\d+")) {
                    roadmapId = last;
                }
            }

            ServerHttpRequest.Builder builder = request.mutate()
                    .header(HEADER_USER_ID, userId.toString())
                    .header(HEADER_USER_ROLE, mappedRole)
                    .header("X-Permissions", permissions);

            if (StringUtils.hasText(roadmapId)) {
                builder.header("X-Roadmap-ID", roadmapId);
            }

            ServerHttpRequest mutated = builder.build();
            return chain.filter(exchange.mutate().request(mutated).build());

        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token for WebSocket handshake");
            return onError(exchange, "TOKEN_EXPIRED", "Token has expired", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("WebSocket handshake JWT validation failed: {}", e.getMessage());
            return onError(exchange, "INVALID_TOKEN", "Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String code, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        String errorJson = String.format(
                "{\"error\":{\"code\":\"%s\",\"message\":\"%s\",\"details\":{},\"timestamp\":\"%s\"}}",
                code, message, Instant.now().toString());
        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorJson.getBytes(StandardCharsets.UTF_8))));
    }

    @Override
    public int getOrder() {
        return -90; // run after JwtAuthenticationGlobalFilter(-100) if that applies; ensures handshake-specific injection
    }
}