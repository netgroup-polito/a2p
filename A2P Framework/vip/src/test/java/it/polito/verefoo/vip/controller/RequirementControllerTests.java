package it.polito.verefoo.vip.controller;

import it.polito.verefoo.vip.exception.common.*;
import it.polito.verefoo.vip.exception.snort.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import javax.validation.ConstraintViolationException;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
public class RequirementControllerTests {
    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testSimpleInput() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-15:48:21.379108  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443"))
                .andExpect(status().isOk());
    }

    @Test
    public void testMissingRequestBody() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0"))
                .andExpect(status().isOk())
                .andExpect(content().xml("<PropertyDefinition/>"));
    }

    @Test
    public void testAlertModeNotFoundException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/InvalidAlertMode")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("alert data"))
                .andExpect(status().isNotFound())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof AlertModeNotFoundException));
    }

    @Test
    public void testAlertPriorityException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-16:30:15.647389  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 0] {ICMP} 192.168.1.10 -> 10.0.0.3"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof AlertPriorityException));
    }

    @Test
    public void testInvalidIPsException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-15:48:21.829472  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.256:54321 -> 192.168.0.2:443"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof InvalidIPsException));
    }

    @Test
    public void testInvalidPortNumbersException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-15:48:21.174902  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:65536 -> 192.168.0.2:443"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof InvalidPortNumbersException));
    }

    @Test
    public void testMalformedAlertException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("malformed alert"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof MalformedAlertException));
    }

    @Test
    public void testParserNotFoundException() throws Exception {
        mockMvc.perform(post("/api/parser/InvalidIDS/1/SomeAlertMode")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("alert data"))
                .andExpect(status().isNotFound())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof ParserNotFoundException));
    }

    /*@Test
    public void testPortMismatchException() throws Exception {
        mockMvc.perform(post("")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content(""))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof PortMismatchException));
    }
    // also include RequestStreamException and StreamProcessingException
    */

    @Test
    public void testRequestPriorityException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0?priority=0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-16:30:15.720472  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {ICMP} 192.168.1.10 -> 10.0.0.3"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof RequestPriorityException));
    }

    @Test
    public void testSamePortTypeException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-15:48:21.472333  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:56789"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof SamePortTypeException));
    }

    @Test
    public void testUnexpectedPortsException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-15:48:21.812947  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {ICMP} 192.168.0.1:54321 -> 192.168.0.2:443"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof UnexpectedPortsException));
    }

    @Test
    public void testUnsupportedAlertModeException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/JsonOut")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("alert data"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof UnsupportedAlertModeException));
    }

    @Test
    public void testProtocolErrorException() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-16:30:15.123457  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {Error} 192.168.1.10 -> 10.0.0.3"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof ProtocolErrorException));
    }

    @Test
    public void testIllegalGraphId() throws Exception {
        mockMvc.perform(post("/api/parser/Snort/3/AlertFastV0?graph=-1")
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("08/06-16:30:15.222234  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.1.1:54321 -> 10.0.0.1:443"))
                .andExpect(status().isBadRequest())
                .andExpect(result -> Assertions.assertTrue(result.getResolvedException() instanceof ConstraintViolationException));
    }
}
