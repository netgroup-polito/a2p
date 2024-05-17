package it.polito.verefoo.vip.parser;

import it.polito.verefoo.vip.config.ParserConfig;
import it.polito.verefoo.vip.exception.common.*;
import it.polito.verefoo.vip.model.Requirement;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.io.InputStream;
import java.util.Set;

public class ParserRegistryTests {
    private ParserRegistry parserRegistry;

    @BeforeEach
    public void setUp() {
        parserRegistry = new ParserRegistry();
    }

    @Test
    public void testDuplicateParserException() {
        AbstractParser mockParser1 = new MockParser1();
        AbstractParser mockParser2 = new MockParser2();

        parserRegistry.registerParser(mockParser1);

        // class names can be the same, but name and version must be different
        Assertions.assertThrows(DuplicateParserException.class, () -> parserRegistry.registerParser(mockParser2));
    }

    @Test
    public void testDuplicateStrategyException() {
        ParserConfig parserConfig = new ParserConfig();
        AbstractParserStrategy mockStrategy1 = new MockStrategy(parserConfig);
        AbstractParserStrategy mockStrategy2 = new MockStrategy2.MockStrategy(parserConfig);

        parserRegistry.registerStrategy(mockStrategy1);

        // class names can't be the same
        Assertions.assertThrows(DuplicateStrategyException.class, () -> parserRegistry.registerStrategy(mockStrategy2));
    }

    @Test
    public void testParserNotFoundException() {
        Assertions.assertThrows(ParserNotFoundException.class, () -> parserRegistry.getParser("NonExistentName", "NonExistentVersion"));
    }

    @Test
    public void testAlertModeNotFoundException() {
        AbstractParser mockParser = new MockParser1();

        parserRegistry.registerParser(mockParser);

        Assertions.assertThrows(AlertModeNotFoundException.class, () -> parserRegistry.getStrategy(mockParser, "NonExistentAlertMode"));
    }

    @Test
    public void testUnsupportedAlertModeException() {
        AbstractParser mockParser = new MockParser1();
        ParserConfig parserConfig = new ParserConfig();
        AbstractParserStrategy mockStrategy = new MockStrategy(parserConfig);

        parserRegistry.registerParser(mockParser);
        parserRegistry.registerStrategy(mockStrategy);

        // MockParser1 is NOT annotated with @SupportedStrategies, so this will throw UnsupportedAlertModeException,
        // since MockStrategy is registered but does not belong to MockParser1
        Assertions.assertThrows(UnsupportedAlertModeException.class, () -> parserRegistry.getStrategy(mockParser, "MockStrategy"));
    }

    private static class MockParser1 extends AbstractParser {
        public MockParser1() {
            super(1);
        }

        @Override
        public String getIdsName() {
            return "MockIDS";
        }

        @Override
        public String getIdsVersion() {
            return "1";
        }

        @Override
        public int getLowestPriorityLevel() {
            return 0;
        }

        @Override
        public int getHighestPriorityLevel() {
            return 0;
        }
    }

    private static class MockParser2 extends AbstractParser {
        public MockParser2() {
            super(1);
        }

        @Override
        public String getIdsName() {
            return "MockIDS";
        }

        @Override
        public String getIdsVersion() {
            return "1";
        }

        @Override
        public int getLowestPriorityLevel() {
            return 0;
        }

        @Override
        public int getHighestPriorityLevel() {
            return 0;
        }
    }

    private static class MockStrategy extends AbstractParserStrategy {
        public MockStrategy(ParserConfig parserConfig) {
            super(parserConfig);
        }

        @Override
        public Set<Requirement> parse(InputStream inputStream, int priority, int graph, int lowestPriorityLevel, int highestPriorityLevel) {
            return null;
        }
    }

    private static class MockStrategy2 {
        private static class MockStrategy extends AbstractParserStrategy {
            public MockStrategy(ParserConfig parserConfig) {
                super(parserConfig);
            }

            @Override
            public Set<Requirement> parse(InputStream inputStream, int priority, int graph, int lowestPriorityLevel, int highestPriorityLevel) {
                return null;
            }
        }
    }
}
