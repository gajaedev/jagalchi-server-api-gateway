package gajeman.jagalchi.jagalchiserver.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Component
public class RequestLoggingGlobalFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingGlobalFilter.class);
    private static final String HEADER_REQUEST_ID = "X-Request-Id";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerWebExchange workingExchange = exchange;
        ServerHttpRequest request = workingExchange.getRequest();
        String requestId = request.getHeaders().getFirst(HEADER_REQUEST_ID);
        if (!StringUtils.hasText(requestId)) {
            requestId = UUID.randomUUID().toString();
            request = request.mutate().header(HEADER_REQUEST_ID, requestId).build();
            workingExchange = workingExchange.mutate().request(request).build();
        }

        String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
        String path = request.getURI().getRawPath();
        String query = request.getURI().getRawQuery();
        String remoteIp = request.getHeaders().getFirst("X-Forwarded-For");
        if (!StringUtils.hasText(remoteIp) && request.getRemoteAddress() != null && request.getRemoteAddress().getAddress() != null) {
            remoteIp = request.getRemoteAddress().getAddress().getHostAddress();
        }

        long start = System.currentTimeMillis();
        String finalRemoteIp = remoteIp;
        String finalRequestId = requestId;
        ServerWebExchange finalExchange = workingExchange;
        log.info("gateway request start requestId={} ip={} method={} path={} query={}", finalRequestId, finalRemoteIp, method, path, query);

        return chain.filter(finalExchange).doFinally(signalType -> {
            ServerHttpResponse response = finalExchange.getResponse();
            response.getHeaders().set(HEADER_REQUEST_ID, finalRequestId);
            int status = response.getStatusCode() != null ? response.getStatusCode().value() : 0;
            long duration = System.currentTimeMillis() - start;
            String userId = finalExchange.getRequest().getHeaders().getFirst("X-User-ID");
            log.info("gateway request end requestId={} status={} durationMs={} userId={} path={}", finalRequestId, status, duration, userId, path);
        });
    }

    @Override
    public int getOrder() {
        return -110;
    }
}
