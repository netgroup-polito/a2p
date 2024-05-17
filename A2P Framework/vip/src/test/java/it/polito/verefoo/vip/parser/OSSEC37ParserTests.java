package it.polito.verefoo.vip.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.polito.verefoo.vip.config.ParserConfig;
import it.polito.verefoo.vip.enums.Lv4proto;
import it.polito.verefoo.vip.exception.common.*;
import it.polito.verefoo.vip.model.Requirement;
import it.polito.verefoo.vip.parser.ossec.parser.OSSEC37Parser;
import it.polito.verefoo.vip.parser.ossec.strategy.JsonOut;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public class OSSEC37ParserTests {
    private static OSSEC37Parser ossec37Parser;
    private static ParserConfig parserConfig;
    private static ObjectMapper objectMapper;
    private static JsonOut jsonOut;

    @BeforeAll
    public static void setUp() {
        ossec37Parser = new OSSEC37Parser();
        parserConfig = new ParserConfig();
        objectMapper = new ObjectMapper();
        jsonOut = new JsonOut(parserConfig, objectMapper);
    }

    @BeforeEach
    public void resetConfig() {
        parserConfig.setAllowSamePortType(false);
    }

    @Test
    public void testSimpleInput() {
        String mockAlerts = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}\n" +
                "{\"rule\": {\"level\": 14}, \"srcip\": \"192.168.0.3\", \"dstip\": \"192.168.0.4\", \"srcport\": \"53\", \"dstport\": \"54000\", \"protocol\": \"UDP\"}";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, 443, Lv4proto.TCP));
        expectedRequirements.add(new Requirement(0, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, null, 0, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testNoAlerts() {
        Set<Requirement> requirements = ossec37Parser.parse(new ByteArrayInputStream(new byte[0]), null, 0, jsonOut);

        Assertions.assertTrue(requirements.isEmpty());
    }

    @Test
    public void testMissingClosingBracket() {
        String missingClosingBracket = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"";

        try (InputStream inputStream = new ByteArrayInputStream(missingClosingBracket.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testMissingSourceIP() {
        String missingSourceIP = "{\"rule\": {\"level\": 10}, \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(missingSourceIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testMissingDestinationIP() {
        String missingDestinationIP = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(missingDestinationIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testExtraCommas() {
        String extraCommas = "{\"rule\": {\"level\": 10},, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\",, \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(extraCommas.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testDuplicateAlerts() {
        String duplicateAlerts = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}\n" +
                "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, 443, Lv4proto.TCP));

        try (InputStream inputStream = new ByteArrayInputStream(duplicateAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, null, 0, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testTranslationToANY() {
        String icmpAlert = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"protocol\": \"ICMP\"}";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, null, Lv4proto.ANY));

        try (InputStream inputStream = new ByteArrayInputStream(icmpAlert.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, null, 0, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testMissingProtocolTranslatesToANY() {
        String missingProtocol = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\"}";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, null, Lv4proto.ANY));

        try (InputStream inputStream = new ByteArrayInputStream(missingProtocol.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, null, 0, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testIllegalPriorityInsideAlert() {
        String illegalPriority = "{\"rule\": {\"level\": 50}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(illegalPriority.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(AlertPriorityException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testIllegalPriorityAsRequestParameter() {
        String illegalPriority = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";
        int priority = 50;

        try (InputStream inputStream = new ByteArrayInputStream(illegalPriority.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(RequestPriorityException.class, () -> ossec37Parser.parse(inputStream, priority, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testPriorityLowerThanDefaultIsDiscarded() {
        String mockAlerts = "{\"rule\": {\"level\": 5}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}\n" +
                "{\"rule\": {\"level\": 14}, \"srcip\": \"192.168.0.3\", \"dstip\": \"192.168.0.4\", \"srcport\": \"53\", \"dstport\": \"54000\", \"protocol\": \"UDP\"}";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, null, 0, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testPriorityLowerThanSpecifiedIsDiscarded() {
        String mockAlerts = "{\"rule\": {\"level\": 5}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}\n" +
                "{\"rule\": {\"level\": 8}, \"srcip\": \"192.168.0.3\", \"dstip\": \"192.168.0.4\", \"srcport\": \"53\", \"dstport\": \"54000\", \"protocol\": \"UDP\"}";
        int priority = 8;
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, priority, 0, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testInvalidSrcIP() {
        String invalidSrcIP = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.256\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(invalidSrcIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(InvalidIPsException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testInvalidDstIP() {
        String invalidDstIP = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.-1.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(invalidDstIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(InvalidIPsException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testInvalidPortNumbers() {
        String invalidSrcPort = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"65536\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(invalidSrcPort.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(InvalidPortNumbersException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testSamePortType() {
        String samePortType = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"50001\", \"protocol\": \"TCP\"}";

        try (InputStream inputStream = new ByteArrayInputStream(samePortType.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(SamePortTypeException.class, () -> ossec37Parser.parse(inputStream, null, 0, jsonOut));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testAllowSamePortType() {
        String samePortType = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"50001\", \"protocol\": \"TCP\"}";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, null, Lv4proto.TCP));
        parserConfig.setAllowSamePortType(true);

        try (InputStream inputStream = new ByteArrayInputStream(samePortType.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, null, 0, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testGraphID() {
        String mockAlerts = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}\n" +
                "{\"rule\": {\"level\": 14}, \"srcip\": \"192.168.0.3\", \"dstip\": \"192.168.0.4\", \"srcport\": \"53\", \"dstport\": \"54000\", \"protocol\": \"UDP\"}";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(10, "192.168.0.1", "192.168.0.2", null, 443, Lv4proto.TCP));
        expectedRequirements.add(new Requirement(10, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = ossec37Parser.parse(inputStream, null, 10, jsonOut);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }
}
