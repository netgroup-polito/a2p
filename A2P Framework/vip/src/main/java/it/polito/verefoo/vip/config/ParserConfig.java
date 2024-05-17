package it.polito.verefoo.vip.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "vip")
public class ParserConfig {
    private boolean allowSamePortType;

    public boolean isAllowSamePortType() {
        return allowSamePortType;
    }

    public void setAllowSamePortType(boolean allowSamePortType) {
        this.allowSamePortType = allowSamePortType;
    }
}
