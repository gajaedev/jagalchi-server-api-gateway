package gajeman.jagalchi.jagalchiserver.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;

@RestController
public class UserOpenApiController {

    private final ObjectMapper objectMapper;

    public UserOpenApiController(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @GetMapping(value = "/docs/user/v3/api-docs", produces = MediaType.APPLICATION_JSON_VALUE)
    public JsonNode userOpenApi() throws IOException {
        ClassPathResource resource = new ClassPathResource("openapi/user-openapi.json");
        try (InputStream inputStream = resource.getInputStream()) {
            return objectMapper.readTree(inputStream);
        }
    }
}
