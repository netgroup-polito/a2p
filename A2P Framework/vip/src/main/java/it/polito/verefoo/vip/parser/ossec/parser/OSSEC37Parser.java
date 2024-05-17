package it.polito.verefoo.vip.parser.ossec.parser;

import it.polito.verefoo.vip.parser.AbstractParser;
import it.polito.verefoo.vip.parser.SupportedStrategies;
import org.springframework.stereotype.Component;

@SupportedStrategies({"JsonOut"})
@Component
public class OSSEC37Parser extends AbstractParser {
    public OSSEC37Parser() {
        // setting default priority for this particular parser
        super(10);
    }

    @Override
    public String getIdsName() {
        return "OSSEC";
    }

    @Override
    public String getIdsVersion() {
        return "3.7";
    }

    // priority level range can be found at: https://www.ossec.net/docs/docs/manual/rules-decoders/rule-levels.html
    @Override
    public int getLowestPriorityLevel() {
        return 0;
    }

    @Override
    public int getHighestPriorityLevel() {
        return 15;
    }
}
