package it.polito.verefoo.vip.parser.snort.parser;

import it.polito.verefoo.vip.parser.AbstractParser;
import it.polito.verefoo.vip.parser.SupportedStrategies;
import org.springframework.stereotype.Component;

@SupportedStrategies({"AlertFastV0"})
@Component
public class Snort3Parser extends AbstractParser {
    public Snort3Parser() {
        // setting default priority for this particular parser
        super(1);
    }

    @Override
    public String getIdsName() {
        return "Snort";
    }

    @Override
    public String getIdsVersion() {
        return "3";
    }

    // priority level range can be found at: https://docs.snort.org/rules/options/general/priority
    @Override
    public int getLowestPriorityLevel() {
        return Integer.MAX_VALUE;
    }

    @Override
    public int getHighestPriorityLevel() {
        return 1;
    }
}
