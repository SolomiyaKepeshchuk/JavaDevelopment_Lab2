package ua.kpi.comsys.collections;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class LogAnalyzerTest {

    private final LogAnalyzer analyzer = new LogAnalyzer();

    private final String log1 =
            "10.0.0.1 ident alice [01/May/2025:07:20:10 +0000] \"GET /index.html HTTP/1.1\" 200 9481";

    private final String log2 =
            "10.0.0.2 ident solomiya [01/May/2025:08:20:10 +0000] \"GET /home HTTP/1.1\" 200 1500";

    private final String log3 =
            "10.0.0.3 ident kate [01/May/2025:09:20:10 +0000] \"POST /login HTTP/1.1\" 200 500";

    @Test
    void testUniqueIps() {
        List<String> logs = List.of(log1, log2, log1, log3);

        Set<String> result = analyzer.getUniqueIps(logs);

        assertEquals(Set.of("10.0.0.1", "10.0.0.2", "10.0.0.3"), result);
    }

    @Test
    void testUniqueIpsWithInvalidLogs() {
        List<String> logs = Arrays.asList(log1, "invalid log", null);

        assertEquals(Set.of("10.0.0.1"), analyzer.getUniqueIps(logs));
    }

    @Test
    void testUniqueIpsWithEmptyList() {
        assertTrue(analyzer.getUniqueIps(List.of()).isEmpty());
    }

    @Test
    void testUniqueIpsWithNull() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getUniqueIps(null)
        );

        assertEquals("logLines cannot be null", exception.getMessage());
    }

    @Test
    void testTopIps() {
        List<String> logs = List.of(log2, log1, log3, log1, log3);

        List<String> result = analyzer.getTopIps(logs, 3);

        assertEquals(List.of("10.0.0.1", "10.0.0.3", "10.0.0.2"), result);
    }

    @Test
    void testTopIpsWithLimit() {
        List<String> logs = List.of(log1, log2, log1);

        assertEquals(List.of("10.0.0.1"), analyzer.getTopIps(logs, 1));
    }

    @Test
    void testTopIpsWithLargeLimit() {
        List<String> logs = List.of(log2, log1);

        assertEquals(List.of("10.0.0.1", "10.0.0.2"), analyzer.getTopIps(logs, 5));
    }

    @Test
    void testTopIpsWithEmptyList() {
        assertTrue(analyzer.getTopIps(List.of(), 3).isEmpty());
    }

    @Test
    void testTopIpsWithInvalidLogs() {
        assertTrue(analyzer.getTopIps(List.of("invalid log"), 3).isEmpty());
    }

    @Test
    void testTopIpsWithNull() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(null, 3)
        );

        assertEquals("logLines cannot be null", exception.getMessage());
    }

    @Test
    void testTopIpsWithInvalidNumber() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(List.of(log1), 0)
        );

        assertEquals("topN must be greater than 0", exception.getMessage());

        assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(List.of(log1), -1)
        );
    }

    @Test
    void testInvalidLogFormats() {
        List<String> logs = List.of(
                log1,
                "invalid log",
                "10.0.0.2 ident solomiya [01/May/2025:08:20:10 +0000] \"GET /home HTTP/1.1\" 20 1500",
                "10.0.0.3 ident solomiya [01/May/2025:08:20:10 +0000] \"GET /home HTTP/1.1\" 200 abc",
                "10.0.0.4 ident solomiya [01/May/2025:08:20:10 +0000] \"GET /home HTTP/1.1\" 200",
                "10.0.0.5 ident solomiya [01/May/2025:08:20:10 +0000] \"GET /home\" 200 1500"
        );

        assertEquals(Set.of("10.0.0.1"), analyzer.getUniqueIps(logs));
        assertEquals(List.of("10.0.0.1"), analyzer.getTopIps(logs, 3));
    }

    @Test
    void testInvalidIp() {
        String invalidLog =
                "10.0.0.999 ident solomiya [01/May/2025:08:20:10 +0000] \"GET /home HTTP/1.1\" 200 1500";

        List<String> logs = List.of(log1, invalidLog);

        assertEquals(Set.of("10.0.0.1"), analyzer.getUniqueIps(logs));
        assertEquals(List.of("10.0.0.1"), analyzer.getTopIps(logs, 2));
    }

    @Test
    void testInvalidHttpVersion() {
        String invalidLog =
                "10.0.0.2 ident solomiya [01/May/2025:08:20:10 +0000] \"GET /home HTTP/abc\" 200 1500";

        List<String> logs = List.of(log1, invalidLog);

        assertEquals(Set.of("10.0.0.1"), analyzer.getUniqueIps(logs));
        assertEquals(List.of("10.0.0.1"), analyzer.getTopIps(logs, 2));
    }
}
