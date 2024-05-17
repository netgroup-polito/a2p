package it.polito.verefoo.vip.parser.ossec.parser;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import it.polito.verefoo.vip.enums.Lv4proto;

public class OSSECUtils {
    // protocol depends on log files that OSSEC analyzes and decoders employed
    // it could be anything, or it could be also be null
    public static Lv4proto toLv4Proto(String protocol) {
        if (protocol == null) {
            return Lv4proto.ANY;
        }

        switch (protocol) {
            case "TCP":
                return Lv4proto.TCP;
            case "UDP":
                return Lv4proto.UDP;
            default:
                return Lv4proto.ANY;
        }
    }

    // https://github.com/ossec/ossec-hids/blob/master/src/analysisd/format/to_json.c#L21
    public static class JsonOutAlert {
        private final Rule rule;
        private final String srcip;
        private final String dstip;
        private final Integer srcport;
        private final Integer dstport;
        private final String protocol;

        @JsonCreator
        public JsonOutAlert(@JsonProperty(value = "rule", required = true) Rule rule,
                            @JsonProperty(value = "srcip", required = true) String srcip,
                            @JsonProperty(value = "dstip", required = true) String dstip,
                            @JsonProperty(value = "srcport") Integer srcport,
                            @JsonProperty(value = "dstport") Integer dstport,
                            @JsonProperty(value = "protocol") String protocol) {
            this.rule = rule;
            this.srcip = srcip;
            this.dstip = dstip;
            this.srcport = srcport;
            this.dstport = dstport;
            this.protocol = protocol;
        }

        public int getLevel() {
            return rule.getLevel();
        }

        public String getSrcip() {
            return srcip;
        }

        public String getDstip() {
            return dstip;
        }

        public Integer getSrcport() {
            return srcport;
        }

        public Integer getDstport() {
            return dstport;
        }

        public String getProtocol() {
            return protocol;
        }
    }

    public static class Rule {
        private final int level;

        @JsonCreator
        public Rule(@JsonProperty(value = "level", required = true) int level) {
            this.level = level;
        }

        public int getLevel() {
            return level;
        }
    }
}
