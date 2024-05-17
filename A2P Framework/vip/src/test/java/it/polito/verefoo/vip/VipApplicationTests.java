package it.polito.verefoo.vip;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import java.io.*;
import java.util.concurrent.*;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
class VipApplicationTests {
    @Autowired
    private MockMvc mockMvc;

    // also test the application and see memory usage when many large request bodies are involved:
    // curl -X POST -H "Content-Type: text/plain" --data-binary @large_test_data.txt http://localhost:8080/api/parser/snort/3/alertfastv0

    @Test
    public void testConcurrentRequests() throws InterruptedException, ExecutionException, UnsupportedEncodingException {
        int numThreads = 6;

        String requestBody1 = "08/06-15:48:21.379108  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443";
        String requestBody2 = "{\"rule\": {\"level\": 14}, \"srcip\": \"192.168.0.2\", \"dstip\": \"192.168.0.3\", \"srcport\": \"53\", \"dstport\": \"54000\", \"protocol\": \"UDP\"}";
        String requestBody3 = "08/06-15:48:21.820720  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 5] {TCP} 192.168.0.1:54321 -> 192.168.0.2:443";
        String requestBody4 = "{\"rule\": {\"level\": 5}, \"srcip\": \"192.168.0.1\", \"dstip\": \"192.168.0.2\", \"srcport\": \"50000\", \"dstport\": \"53\", \"protocol\": \"UDP\"}";
        String requestBody5 = "08/06-15:49:11.124352  [**] [1:2:3] Test Requirement [**] [Classification: Test] [Priority: 1] {UDP} 192.168.0.3:53 -> 192.168.0.4:56789";
        String requestBody6 = "{\"rule\": {\"level\": 10}, \"srcip\": \"192.168.0.3\", \"dstip\": \"192.168.0.4\", \"srcport\": \"50000\", \"dstport\": \"443\", \"protocol\": \"TCP\"}";

        String expectedResponseBody1 = "<PropertyDefinition><Property graph=\"0\" name=\"IsolationProperty\" src=\"192.168.0.1\" dst=\"192.168.0.2\" dst_port=\"443\" lv4proto=\"TCP\"/></PropertyDefinition>";
        String expectedResponseBody2 = "<PropertyDefinition><Property graph=\"0\" name=\"IsolationProperty\" src=\"192.168.0.2\" dst=\"192.168.0.3\" src_port=\"53\" lv4proto=\"UDP\"/></PropertyDefinition>";
        String expectedResponseBody3 = "<PropertyDefinition/>";
        String expectedResponseBody4 = "<PropertyDefinition/>";
        String expectedResponseBody5 = "<PropertyDefinition><Property graph=\"0\" name=\"IsolationProperty\" src=\"192.168.0.3\" dst=\"192.168.0.4\" src_port=\"53\" lv4proto=\"UDP\"/></PropertyDefinition>";
        String expectedResponseBody6 = "<PropertyDefinition><Property graph=\"0\" name=\"IsolationProperty\" src=\"192.168.0.3\" dst=\"192.168.0.4\" dst_port=\"443\" lv4proto=\"TCP\"/></PropertyDefinition>";

        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        // startLatch to start every thread at (almost) the same time
        // finishLatch to wait until all threads have finished their execution
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(numThreads);

        Future<MockHttpServletResponse> future1 = executor.submit(() -> {
            startLatch.await();
            MockHttpServletResponse response = mockMvc.perform(post("/api/parser/snort/3/alertfastv0")
                            .content(requestBody1)
                            .contentType(MediaType.TEXT_PLAIN))
                    .andReturn().getResponse();
            finishLatch.countDown();
            return response;
        });

        Future<MockHttpServletResponse> future2 = executor.submit(() -> {
            startLatch.await();
            MockHttpServletResponse response = mockMvc.perform(post("/api/parser/ossec/3.7/jsonout")
                            .content(requestBody2)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andReturn().getResponse();
            finishLatch.countDown();
            return response;
        });

        Future<MockHttpServletResponse> future3 = executor.submit(() -> {
            startLatch.await();
            MockHttpServletResponse response = mockMvc.perform(post("/api/parser/snort/3/alertfastv0")
                            .content(requestBody3)
                            .contentType(MediaType.TEXT_PLAIN))
                    .andReturn().getResponse();
            finishLatch.countDown();
            return response;
        });

        Future<MockHttpServletResponse> future4 = executor.submit(() -> {
            startLatch.await();
            MockHttpServletResponse response = mockMvc.perform(post("/api/parser/ossec/3.7/jsonout")
                            .content(requestBody4)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andReturn().getResponse();
            finishLatch.countDown();
            return response;
        });

        Future<MockHttpServletResponse> future5 = executor.submit(() -> {
            startLatch.await();
            MockHttpServletResponse response = mockMvc.perform(post("/api/parser/snort/3/alertfastv0")
                            .content(requestBody5)
                            .contentType(MediaType.TEXT_PLAIN))
                    .andReturn().getResponse();
            finishLatch.countDown();
            return response;
        });

        Future<MockHttpServletResponse> future6 = executor.submit(() -> {
            startLatch.await();
            MockHttpServletResponse response = mockMvc.perform(post("/api/parser/ossec/3.7/jsonout")
                            .content(requestBody6)
                            .contentType(MediaType.APPLICATION_JSON))
                    .andReturn().getResponse();
            finishLatch.countDown();
            return response;
        });

        executor.shutdown();

        startLatch.countDown();

        finishLatch.await();

        Assertions.assertThat(future1.get().getStatus()).isEqualTo(HttpStatus.OK.value());
        Assertions.assertThat(future1.get().getContentAsString()).isEqualTo(expectedResponseBody1);

        Assertions.assertThat(future2.get().getStatus()).isEqualTo(HttpStatus.OK.value());
        Assertions.assertThat(future2.get().getContentAsString()).isEqualTo(expectedResponseBody2);

        Assertions.assertThat(future3.get().getStatus()).isEqualTo(HttpStatus.OK.value());
        Assertions.assertThat(future3.get().getContentAsString()).isEqualTo(expectedResponseBody3);

        Assertions.assertThat(future4.get().getStatus()).isEqualTo(HttpStatus.OK.value());
        Assertions.assertThat(future4.get().getContentAsString()).isEqualTo(expectedResponseBody4);

        Assertions.assertThat(future5.get().getStatus()).isEqualTo(HttpStatus.OK.value());
        Assertions.assertThat(future5.get().getContentAsString()).isEqualTo(expectedResponseBody5);

        Assertions.assertThat(future6.get().getStatus()).isEqualTo(HttpStatus.OK.value());
        Assertions.assertThat(future6.get().getContentAsString()).isEqualTo(expectedResponseBody6);
    }
}
