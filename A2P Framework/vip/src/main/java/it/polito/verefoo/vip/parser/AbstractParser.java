package it.polito.verefoo.vip.parser;

import it.polito.verefoo.vip.exception.common.*;
import it.polito.verefoo.vip.model.Requirement;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.util.Set;

public abstract class AbstractParser {
    @Autowired
    private ParserRegistry parserRegistry;

    private final int defaultPriority;

    protected AbstractParser(int defaultPriority) {
        this.defaultPriority = defaultPriority;
    }

    // needs to execute AFTER dependency injection has taken place.
    // when the AbstractParser constructor is called,
    // the ParserRegistry is not yet injected and is null
    @PostConstruct
    public void registerParser() {
        parserRegistry.registerParser(this);
    }

    public abstract String getIdsName();

    public abstract String getIdsVersion();

    public abstract int getLowestPriorityLevel();

    public abstract int getHighestPriorityLevel();

    public Set<Requirement> parse(InputStream inputStream, Integer priority, Integer graph, AbstractParserStrategy strategy) {
        if (strategy == null) {
            throw new StrategyNotSetException();
        }

        return strategy.parse(inputStream,
                (priority == null) ? defaultPriority : priority,
                (graph == null) ? 0 : graph,
                getLowestPriorityLevel(),
                getHighestPriorityLevel()
        );
    }
}
