package it.polito.verefoo.vip.parser;

import it.polito.verefoo.vip.config.ParserConfig;
import it.polito.verefoo.vip.exception.common.*;
import it.polito.verefoo.vip.exception.snort.ProtocolErrorException;
import it.polito.verefoo.vip.model.Requirement;
import it.polito.verefoo.vip.parser.snort.parser.Snort3Parser;
import it.polito.verefoo.vip.parser.snort.strategy.AlertFastV0;
import it.polito.verefoo.vip.enums.Lv4proto;
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

public class Snort3ParserTests {
    private static Snort3Parser snort3Parser;
    private static ParserConfig parserConfig;
    private static AlertFastV0 alertFastV0;

    @BeforeAll
    public static void setUp() {
        snort3Parser = new Snort3Parser();
        parserConfig = new ParserConfig();
        alertFastV0 = new AlertFastV0(parserConfig);
    }

    // need to reset parser config before each test, otherwise there could be conflicts
    @BeforeEach
    public void resetParserConfig() {
        // can be changed within the individual test before parsing, if necessary
        parserConfig.setAllowSamePortType(false);
    }

    @Test
    public void testSimpleInput() {
        String mockAlerts = "08/06-15:48:21.379108  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443\n" +
                "08/06-15:49:11.124352  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {UDP} 192.168.0.3:53 -> 192.168.0.4:56789";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, 443, Lv4proto.TCP));
        expectedRequirements.add(new Requirement(0, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = snort3Parser.parse(inputStream, null, 0, alertFastV0);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testNoAlerts() {
        Set<Requirement> requirements = snort3Parser.parse(new ByteArrayInputStream(new byte[0]), null, 0, alertFastV0);

        Assertions.assertTrue(requirements.isEmpty());
    }

    @Test
    public void testMissingCurlyBracesAroundProtocol() {
        String missingCurlyBraces = "08/07-12:33:56.892749  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] TCP 192.168.0.1:54321 -> 192.168.0.2:443";

        try (InputStream inputStream = new ByteArrayInputStream(missingCurlyBraces.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testMissingSourceIP() {
        String missingSourceIP = "08/07-14:11:51.629501  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} :54321 -> 192.168.0.2:443";

        try (InputStream inputStream = new ByteArrayInputStream(missingSourceIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testMissingDestinationIP() {
        String missingDestinationIP = "08/07-14:11:51.629501  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> :443";

        try (InputStream inputStream = new ByteArrayInputStream(missingDestinationIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testExtraSpaces() {
        String extraSpaces = "08/08-17:31:13.174392  [**] [1:2:3] Test Requirement [**]  [Classification: Test]  [Priority: 1 ]  {TCP}  192.168.0.1:54321   ->   192.168.0.2:443";

        try (InputStream inputStream = new ByteArrayInputStream(extraSpaces.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(MalformedAlertException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testDuplicateAlerts() {
        String duplicateAlerts = "08/06-15:48:21.379108  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443\n" +
                "08/06-15:48:21.379108  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, 443, Lv4proto.TCP));

        try (InputStream inputStream = new ByteArrayInputStream(duplicateAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = snort3Parser.parse(inputStream, null, 0, alertFastV0);

            // duplicates should be discarded
            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testTranslationToOTHER() {
        String icmpAlert = "08/06-16:30:15.123473  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {ICMP} 192.168.0.1 -> 192.168.0.2";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, null, Lv4proto.OTHER));

        try (InputStream inputStream = new ByteArrayInputStream(icmpAlert.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = snort3Parser.parse(inputStream, null, 0, alertFastV0);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testErrorProtocol() {
        String errorAlert = "08/06-16:30:15.123457  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {Error} 192.168.1.10 -> 10.0.0.3";

        try (InputStream inputStream = new ByteArrayInputStream(errorAlert.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(ProtocolErrorException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testIllegalPriorityInsideAlert() {
        String illegalPriority = "08/06-16:30:15.647389  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 0] {ICMP} 192.168.1.10 -> 10.0.0.3";

        try (InputStream inputStream = new ByteArrayInputStream(illegalPriority.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(AlertPriorityException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testIllegalPriorityAsRequestParameter() {
        String illegalPriority = "08/06-16:30:15.720472  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {ICMP} 192.168.1.10 -> 10.0.0.3";
        int priority = 0;

        try (InputStream inputStream = new ByteArrayInputStream(illegalPriority.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(RequestPriorityException.class, () -> snort3Parser.parse(inputStream, priority, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testPriorityLowerThanDefaultIsDiscarded() {
        String mockAlerts = "08/06-15:48:21.917451  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 5000] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443\n" +
                "08/06-15:49:11.227492  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {UDP} 192.168.0.3:53 -> 192.168.0.4:56789";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = snort3Parser.parse(inputStream, null, 0, alertFastV0);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testPriorityLowerThanSpecifiedIsDiscarded() {
        String mockAlerts = "08/06-15:48:21.184932  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 5000] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443\n" +
                "08/06-15:49:11.282014  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 50] {UDP} 192.168.0.3:53 -> 192.168.0.4:56789";
        int priority = 50;
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = snort3Parser.parse(inputStream, priority, 0, alertFastV0);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testInvalidSrcIP() {
        String invalidSrcIP = "08/06-15:48:21.829472  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.256:54321 -> 192.168.0.2:443";

        try (InputStream inputStream = new ByteArrayInputStream(invalidSrcIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(InvalidIPsException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testInvalidDstIP() {
        String invalidDstIP = "08/06-15:48:21.628104  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.-1.2:443";

        try (InputStream inputStream = new ByteArrayInputStream(invalidDstIP.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(InvalidIPsException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testInvalidPortNumbers() {
        String invalidSrcPort = "08/06-15:48:21.174902  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:65536 -> 192.168.0.2:443";

        try (InputStream inputStream = new ByteArrayInputStream(invalidSrcPort.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(InvalidPortNumbersException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testUnexpectedPorts() {
        String unexpectedPorts = "08/06-15:48:21.812947  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {ICMP} 192.168.0.1:54321 -> 192.168.0.2:443";

        try (InputStream inputStream = new ByteArrayInputStream(unexpectedPorts.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(UnexpectedPortsException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testSamePortType() {
        String samePortType = "08/06-15:48:21.472333  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:56789";

        try (InputStream inputStream = new ByteArrayInputStream(samePortType.getBytes(StandardCharsets.UTF_8))) {
            Assertions.assertThrows(SamePortTypeException.class, () -> snort3Parser.parse(inputStream, null, 0, alertFastV0));
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    void testAllowSamePortType() {
        String samePortType = "08/06-15:48:21.839521  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:56789";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(0, "192.168.0.1", "192.168.0.2", null, null, Lv4proto.TCP));
        parserConfig.setAllowSamePortType(true);

        try (InputStream inputStream = new ByteArrayInputStream(samePortType.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = snort3Parser.parse(inputStream, null, 0, alertFastV0);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }

    @Test
    public void testGraphID() {
        String mockAlerts = "08/06-15:48:21.643931  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443\n" +
                "08/06-15:49:11.712047  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {UDP} 192.168.0.3:53 -> 192.168.0.4:56789";
        Set<Requirement> expectedRequirements = new HashSet<>();
        expectedRequirements.add(new Requirement(10, "192.168.0.1", "192.168.0.2", null, 443, Lv4proto.TCP));
        expectedRequirements.add(new Requirement(10, "192.168.0.3", "192.168.0.4", 53, null, Lv4proto.UDP));

        try (InputStream inputStream = new ByteArrayInputStream(mockAlerts.getBytes(StandardCharsets.UTF_8))) {
            Set<Requirement> actualRequirements = snort3Parser.parse(inputStream, null, 10, alertFastV0);

            Assertions.assertEquals(expectedRequirements, actualRequirements);
        } catch (IOException e) {
            Assertions.fail("Error processing input stream.", e);
        }
    }
}
