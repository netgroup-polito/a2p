package it.polito.verefoo.vip.parser.snort.parser;

import it.polito.verefoo.vip.enums.Lv4proto;
import it.polito.verefoo.vip.exception.snort.ProtocolErrorException;
import it.polito.verefoo.vip.parser.AbstractParserStrategy;

public class SnortUtils {
    // VEREFOO only supports transport protocols
    // Snort supports a range of protocols spanning multiple layers, as described in:
    // https://github.com/snort3/snort3/blob/master/src/protocols/packet.cc#L150
    public static Lv4proto toLv4Proto(String protocol, AbstractParserStrategy.ParsingContext context) {
        // "None" is translated to "OTHER" (for now).
        // maybe in the future VEREFOO will also support "NONE" as lv4proto
        switch (protocol) {
            case "TCP":
                return Lv4proto.TCP;
            case "UDP":
                return Lv4proto.UDP;
            case "Error":
                throw new ProtocolErrorException(context);
            default:
                return Lv4proto.OTHER;
        }
    }
}
