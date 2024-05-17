package it.polito.verefoo.vip.parser.ossec.strategy;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.polito.verefoo.vip.config.ParserConfig;
import it.polito.verefoo.vip.exception.common.MalformedAlertException;
import it.polito.verefoo.vip.exception.common.StreamProcessingException;
import it.polito.verefoo.vip.model.Requirement;
import it.polito.verefoo.vip.parser.AbstractParserStrategy;
import it.polito.verefoo.vip.parser.ossec.parser.OSSECUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;

@Component
public class JsonOut extends AbstractParserStrategy {
    // objectMapper can be moved inside parse() but it would be less efficient,
    // since a new instance would be created each time parse() is called
    private final ObjectMapper objectMapper;

    @Autowired
    public JsonOut(ParserConfig config, ObjectMapper objectMapper) {
        super(config);
        this.objectMapper = objectMapper;
    }

    @Override
    public Set<Requirement> parse(InputStream inputStream, int priority, int graph, int lowestPriorityLevel, int highestPriorityLevel) {
        Set<Requirement> requirementSet = new HashSet<>();

        ParsingContext context = new ParsingContext();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            // ossec json alerts are json objects separated by newline characters
            while ((line = reader.readLine()) != null) {
                try {
                    context.setAlertString(line);
                    context.setGraph(graph);

                    OSSECUtils.JsonOutAlert alert = objectMapper.readValue(line, OSSECUtils.JsonOutAlert.class);

                    context.setAlertPriority(alert.getLevel());

                    if (shouldFilter(context, priority, lowestPriorityLevel, highestPriorityLevel))
                        continue;

                    context.setLv4proto(OSSECUtils.toLv4Proto(alert.getProtocol()));
                    context.setSrc(alert.getSrcip());
                    context.setSrcPort(alert.getSrcport());
                    context.setDst(alert.getDstip());
                    context.setDstPort(alert.getDstport());

                    checkAlert(context);

                    removeEphemeralPorts(context);

                    requirementSet.add(context.toRequirement());
                } catch (IOException e) {
                    throw new MalformedAlertException(context);
                }
            }
        } catch (IOException e) {
            throw new StreamProcessingException();
        }

        return requirementSet;
    }
}
