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
 * JWT 인증 GlobalFilter
 * 
 * User 모듈의 JWT 토큰을 검증하고, Claims를 추출하여
 * X-User-ID, X-User-Role 헤더로 변환하여 downstream 서비스로 전달
 */
@Slf4j
@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_USER_ID = "X-User-ID";
    private static final String HEADER_USER_ROLE = "X-User-Role";
    private static final String TOKEN_PREFIX = "Bearer ";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // OPTIONS(preflight) 요청은 CORS 처리로 넘기기 위해 인증 생략
        if (request.getMethod() != null && "OPTIONS".equalsIgnoreCase(request.getMethod().name())) {
            log.debug("Preflight OPTIONS request - skipping auth: {}", path);
            return chain.filter(exchange);
        }

        // 인증이 필요없는 경로는 통과
        if (isPublicPath(path)) {
            log.debug("Public path accessed: {}", path);
            return chain.filter(exchange);
        }

        // Authorization 헤더 추출. 없으면 access_token 쿼리 파라미터를 대체로 허용 (브라우저 fetch/SockJS 편의용)
        String authHeader = request.getHeaders().getFirst(HEADER_AUTHORIZATION);
        String token = null;

        if (StringUtils.hasText(authHeader) && authHeader.startsWith(TOKEN_PREFIX)) {
            token = authHeader.substring(TOKEN_PREFIX.length());
        } else {
            // 쿼리 파라미터로 토큰 전달 허용 (테스트/브라우저에서 사용)
            String tokenParam = request.getQueryParams().getFirst("access_token");
            if (StringUtils.hasText(tokenParam)) {
                token = tokenParam;
                log.debug("Using access_token query param for authentication for path: {}", path);
            } else {
                log.warn("Missing or invalid Authorization header for path: {}", path);
                return onError(exchange, "UNAUTHORIZED", "Authorization header is missing or invalid", HttpStatus.UNAUTHORIZED);
            }
        }

        try {
            // JWT 검증 및 Claims 추출
            Claims claims = parseToken(token);
            
            // Token type 검증
            String tokenType = claims.get("type", String.class);
            if (!"ACCESS_TOKEN".equals(tokenType)) {
                log.warn("Invalid token type: {}", tokenType);
                return onError(exchange, "INVALID_TOKEN", "Invalid token type", HttpStatus.UNAUTHORIZED);
            }

            // User ID 및 Role 추출
            Long userId = claims.get("id", Long.class);
            String role = claims.get("role", String.class);

            if (userId == null || role == null) {
                log.warn("Missing user ID or role in token claims");
                return onError(exchange, "INVALID_TOKEN", "Invalid token claims", HttpStatus.UNAUTHORIZED);
            }

            // Role 매핑 (User 모듈 → Node 모듈)
            String mappedRole = mapRole(role);

            log.info("JWT authenticated: userId={}, originalRole={}, mappedRole={}, path={}", 
                    userId, role, mappedRole, path);

            // 헤더 추가
            // 기본 권한 매핑 (간단한 권한 세트 제공)
            String permissions = mapPermissions(mappedRole);

            // 가능하면 roadmapId 추출 (쿼리 파라미터 또는 경로)
            String roadmapId = request.getQueryParams().getFirst("roadmapId");
            if (!StringUtils.hasText(roadmapId)) {
                // 경로에서 /roadmap/{id} 패턴을 찾아 추출
                java.util.regex.Matcher m = java.util.regex.Pattern.compile("/roadmap/(\\d+)").matcher(path);
                if (m.find()) {
                    roadmapId = m.group(1);
                } else {
                    // 기존 방식: 마지막 세그먼트가 숫자라면 사용
                    String[] segments = path.split("/");
                    String last = segments.length > 0 ? segments[segments.length - 1] : "";
                    if (last.matches("\\d+")) {
                        roadmapId = last;
                    }
                }
            }

            ServerHttpRequest.Builder builder = request.mutate()
                    .header(HEADER_USER_ID, userId.toString())
                    .header(HEADER_USER_ROLE, mappedRole)
                    .header("X-Permissions", permissions);

            if (StringUtils.hasText(roadmapId)) {
                builder.header("X-Roadmap-ID", roadmapId);
            }

            ServerHttpRequest mutatedRequest = builder.build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (ExpiredJwtException e) {
            log.warn("Expired JWT token for path: {}", path);
            return onError(exchange, "TOKEN_EXPIRED", "Token has expired", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("JWT validation failed for path: {}. Error: {}", path, e.getMessage());
            return onError(exchange, "INVALID_TOKEN", "Invalid token", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * JWT 토큰 파싱 및 검증
     */
    private Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Role 매핑: User 모듈 → Node 모듈
     * STUDENT → USER
     * TEACHER → ADMIN
     * ADMIN → ADMIN
     */
    private String mapRole(String userRole) {
        return switch (userRole.toUpperCase()) {
            case "STUDENT" -> "USER";
            case "TEACHER", "ADMIN" -> "ADMIN";
            default -> {
                log.warn("Unknown role: {}, defaulting to USER", userRole);
                yield "USER";
            }
        };
    }

    /**
     * Role 매핑: User 모듈 → Node 모듈
     * STUDENT → USER
     * TEACHER → ADMIN
     * ADMIN → ADMIN
     */
    private String mapPermissions(String mappedRole) {
        return switch (mappedRole.toUpperCase()) {
            case "ADMIN" -> "ALL";
            case "USER" -> "READ,WRITE";
            default -> "READ";
        };
    }

    /**
     * 인증이 필요없는 공개 경로 확인
     */
    private boolean isPublicPath(String path) {
        // Allow public access to signup and auth endpoints
        if (path == null) return false;
        if (path.equals("/users")) return true; // signup
        if (path.startsWith("/users/auth/login")) return true;
        if (path.startsWith("/users/auth/refresh")) return true;
        if (path.startsWith("/users/auth/password-reset")) return true;
        if (path.startsWith("/users/verification")) return true;
        if (path.startsWith("/users") && path.contains("/oauth2/")) return true;
        if (path.equals("/health") || path.equals("/actuator/health")) return true;
        return false;
    }

    /**
     * 에러 응답 반환 (공통 에러 포맷)
     */
    private Mono<Void> onError(ServerWebExchange exchange, String code, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");

        String errorJson = String.format(
                "{\"error\":{\"code\":\"%s\",\"message\":\"%s\",\"details\":{},\"timestamp\":\"%s\"}}",
                code, message, Instant.now().toString());

        return response.writeWith(Mono.just(response.bufferFactory()
                .wrap(errorJson.getBytes(StandardCharsets.UTF_8))));
    }

    @Override
    public int getOrder() {
        return -100; // 다른 필터보다 먼저 실행
    }
}
