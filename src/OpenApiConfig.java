import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.media.Schema;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .components(new Components()
                        .addSchemas("EventDTO", new Schema<>()
                                .addProperty("name", new Schema<String>().type("string").example("string"))
                                .addProperty("businessDate", new Schema<String>()
                                        .type("string")
                                        .format("yyyy-MM")
                                        .example("yyyy-MM")))
                        .addSchemas("ProductRequest", new Schema<>()
                                .addProperty("name", new Schema<String>().type("string").example("string"))
                                .addProperty("businessDate", new Schema<String>()
                                        .type("string")
                                        .format("yyyy-MM-dd")
                                        .example("yyyy-MM-dd"))));
    }

}
