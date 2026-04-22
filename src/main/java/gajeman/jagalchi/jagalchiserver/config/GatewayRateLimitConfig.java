package gajeman.jagalchi.jagalchiserver.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

@Configuration
public class GatewayRateLimitConfig {

    @Bean
    public KeyResolver clientKeyResolver() {
        return exchange -> {
            ServerHttpRequest request = exchange.getRequest();

            String userId = request.getHeaders().getFirst("X-User-ID");
            if (StringUtils.hasText(userId)) {
                return Mono.just("user:" + userId);
            }

            String forwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
            if (StringUtils.hasText(forwardedFor)) {
                String clientIp = forwardedFor.split(",")[0].trim();
                if (StringUtils.hasText(clientIp)) {
                    return Mono.just("ip:" + clientIp);
                }
            }

            if (request.getRemoteAddress() != null && request.getRemoteAddress().getAddress() != null) {
                return Mono.just("ip:" + request.getRemoteAddress().getAddress().getHostAddress());
            }

            return Mono.just("ip:unknown");
        };
    }
}
