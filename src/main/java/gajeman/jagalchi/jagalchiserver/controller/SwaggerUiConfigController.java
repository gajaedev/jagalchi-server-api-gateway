package gajeman.jagalchi.jagalchiserver.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
public class SwaggerUiConfigController {

    @Value("${SWAGGER_BASE_URL:https://api.jagalchi.dev}")
    private String swaggerBaseUrl;

    @GetMapping(value = "/swagger-config.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> swaggerConfig() {
        return Map.of(
                "configUrl", "/swagger-config.json",
                "oauth2RedirectUrl", swaggerBaseUrl + "/webjars/swagger-ui/oauth2-redirect.html",
                "validatorUrl", "",
                "urls", List.of(
                        Map.of("name", "user-service", "url", "/docs/user/v3/api-docs"),
                        Map.of("name", "node-service", "url", "/docs/node/v3/api-docs"),
                        Map.of("name", "roadmap-service", "url", "/docs/roadmap/v3/api-docs"),
                        Map.of("name", "ai-service", "url", "/ai/schema/")
                )
        );
    }
}
