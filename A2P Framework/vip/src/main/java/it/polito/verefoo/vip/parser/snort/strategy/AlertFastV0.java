package it.polito.verefoo.vip.parser.snort.strategy;

import it.polito.verefoo.vip.config.ParserConfig;
import it.polito.verefoo.vip.exception.common.MalformedAlertException;
import it.polito.verefoo.vip.exception.common.StreamProcessingException;
import it.polito.verefoo.vip.model.Requirement;
import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import it.polito.verefoo.vip.parser.snort.parser.SnortUtils;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class AlertFastV0 extends AbstractParserStrategy {
    // alert_fast format (can be found inside alert_fast.cc, under the FastLogger::alert method):
    // timestamp [Action_String] [**] [gid:sid:rev] <interface> Message [**] [Classification: classification description] [Priority: priority level] [AppID: application ID] {protocol} srcIP:srcPort -> destIp:destPort
    // some fields are optional (e.g. ports, for ICMP-related alerts), a typical alert looks like this:
    // 08/06-15:48:21.379108  [**] [1:2:3] Sample Requirement [**] [Classification: Sample] [Priority: 1] {TCP} 10.0.0.1:54321 -> 10.0.0.2:80

    // the alert_fast plugin version can be found inside alert_fast.cc under the declaration of the fast_api static variable.
    // fast_api is of type LogApi, which contains a BaseApi field (the first one) that in turn contains the plugin version.
    // EXAMPLE (code inside alert_fast):
    /*
        static LogApi fast_api
        {
            {
                PT_LOGGER,
                sizeof(LogApi),
                LOGAPI_VERSION,
                0,
                API_RESERVED,
                API_OPTIONS,
                S_NAME,
                s_help,
                mod_ctor,
                mod_dtor
            },
            OUTPUT_TYPE_FLAG__ALERT,
            fast_ctor,
            fast_dtor
        };
    */
    // in this case, plugin version for alert_fast is "0" (fourth field)

    private static final Pattern PATTERN = Pattern.compile("\\[Priority: (\\d+)] \\{(\\w+)} ([^\\s:]+)(?::(\\d+))? -> ([^\\s:]+)(?::(\\d+))?");

    public AlertFastV0(ParserConfig parserConfig) {
        super(parserConfig);
    }

    @Override
    public Set<Requirement> parse(InputStream inputStream, int priority, int graph, int lowestPriorityLevel, int highestPriorityLevel) {
        Set<Requirement> requirementSet = new HashSet<>();

        // create local ParsingContext, so there's no interference between concurrently parsing threads
        ParsingContext context = new ParsingContext();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // remember to update context with newly extracted info as soon as you can!
                context.setAlertString(line);
                context.setGraph(graph);

                Matcher matcher = PATTERN.matcher(line);

                if (!matcher.find()) {
                    throw new MalformedAlertException(context);
                }

                context.setAlertPriority(Integer.parseInt(matcher.group(1)));

                // skip alert if priority is low
                if (shouldFilter(context, priority, lowestPriorityLevel, highestPriorityLevel))
                    continue;

                context.setLv4proto(SnortUtils.toLv4Proto(matcher.group(2), context)); // extract lv4proto from protocol
                context.setSrc(matcher.group(3));
                context.setSrcPort(matcher.group(4) != null ? Integer.valueOf(matcher.group(4)) : null);
                context.setDst(matcher.group(5));
                context.setDstPort(matcher.group(6) != null ? Integer.valueOf(matcher.group(6)) : null);

                // check alert for any inconsistencies
                checkAlert(context);

                // ephemeral ports should not be included in output requirements
                removeEphemeralPorts(context);

                requirementSet.add(context.toRequirement());
            }
        } catch (IOException e) {
            throw new StreamProcessingException();
        }

        return requirementSet;
    }
}
