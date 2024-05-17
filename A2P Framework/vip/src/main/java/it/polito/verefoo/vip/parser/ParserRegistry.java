package it.polito.verefoo.vip.parser;

import it.polito.verefoo.vip.exception.common.*;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class ParserRegistry {
    private final Map<String, AbstractParser> parsers = new HashMap<>();
    private final Map<String, AbstractParserStrategy> strategies = new HashMap<>();
    private final Map<Class<? extends AbstractParser>, Set<String>> parserStrategyMap = new HashMap<>();

    public AbstractParser getParser(String idsName, String idsVersion) {
        AbstractParser parser = parsers.get(idsName.toLowerCase() + idsVersion.toLowerCase());

        if (parser == null) {
            throw new ParserNotFoundException(idsName, idsVersion);
        }

        return parser;
    }

    public AbstractParserStrategy getStrategy(AbstractParser parser, String alertMode) {
        // a strategy is the class that implements all the logic to parse an alert mode
        AbstractParserStrategy strategy = strategies.get(alertMode.toLowerCase());

        if (strategy == null) {
            throw new AlertModeNotFoundException(alertMode);
        }

        Set<String> supportedStrategies = parserStrategyMap.get(parser.getClass());
        if (supportedStrategies == null || !supportedStrategies.contains(strategy.getClass().getSimpleName().toLowerCase())) {
            throw new UnsupportedAlertModeException(parser.getIdsName(), parser.getIdsVersion(), alertMode, supportedStrategies);
        }

        return strategy;
    }

    public void registerParser(AbstractParser parser) {
        String key = parser.getIdsName().toLowerCase() + parser.getIdsVersion().toLowerCase();

        if (parsers.containsKey(key)) {
            throw new DuplicateParserException(parser.getIdsName(), parser.getIdsVersion());
        }

        parsers.put(key, parser);

        SupportedStrategies annotation = parser.getClass().getAnnotation(SupportedStrategies.class);
        if (annotation != null) {
            Set<String> lowercaseStrategyNames = Arrays.stream(annotation.value())
                    .map(String::toLowerCase)
                    .collect(Collectors.toSet());

            parserStrategyMap.put(parser.getClass(), lowercaseStrategyNames);
        }
    }

    public void registerStrategy(AbstractParserStrategy strategy) {
        String strategyName = strategy.getClass().getSimpleName();
        String lowercaseStrategyName = strategyName.toLowerCase();

        if (strategies.containsKey(lowercaseStrategyName)) {
            throw new DuplicateStrategyException(strategyName);
        }

        strategies.put(lowercaseStrategyName, strategy);
    }
}
