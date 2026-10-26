
package ua.kpi.comsys.collections;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class LogAnalyzer {

    public Set<String> getUniqueIps(List<String> logLines) {
        if (logLines == null) {
            throw new IllegalArgumentException("logLines cannot be null");
        }

        Set<String> uniqueIps = new HashSet<>();

        for (String line : logLines) {
            String ip = getIpFromLog(line);

            if (ip != null) {
                uniqueIps.add(ip);
            }
        }

        return uniqueIps;
    }

    public List<String> getTopIps(List<String> logLines, int topN) {
        if (logLines == null) {
            throw new IllegalArgumentException("logLines cannot be null");
        }

        if (topN <= 0) {
            throw new IllegalArgumentException("topN must be greater than 0");
        }

        Map<String, Integer> counts = new HashMap<>();

        for (String line : logLines) {
            String ip = getIpFromLog(line);

            if (ip != null) {
                counts.put(ip, counts.getOrDefault(ip, 0) + 1);
            }
        }

        List<String> ips = new ArrayList<>(counts.keySet());

        ips.sort((first, second) -> {
            int difference = Integer.compare(
                    counts.get(second), counts.get(first)
            );

            if (difference != 0) {
                return difference;
            }

            return first.compareTo(second);
        });

        return new ArrayList<>(ips.subList(0, Math.min(topN, ips.size())));
    }

    private String getIpFromLog(String line) {
        if (line == null || line.isBlank()) {
            return null;
        }

        String[] sections = line.trim().split("\"", -1);

        if (sections.length != 3) {
            return null;
        }

        if (!sections[0].endsWith(" ") || !sections[2].startsWith(" ")) {
            return null;
        }

        String[] start = sections[0].trim().split("\\s+", 4);
        String[] end = sections[2].trim().split("\\s+");

        if (start.length != 4 || end.length != 2) {
            return null;
        }

        if (!isValidIp(start[0])) {
            return null;
        }

        if (!start[3].startsWith("[") || !start[3].endsWith("]")) {
            return null;
        }

        String date = start[3].substring(1, start[3].length() - 1);

        try {
            DateTimeFormatter format = DateTimeFormatter.ofPattern(
                    "dd/MMM/uuuu:HH:mm:ss Z", Locale.ENGLISH
            );

            OffsetDateTime.parse(date, format);
        } catch (DateTimeParseException e) {
            return null;
        }

        String requestText = sections[1].trim();

        if (!requestText.equals("-")) {
            String[] request = requestText.split("\\s+");

            if (request.length != 3 ||
                    !request[2].matches("HTTP/[0-9]+\\.[0-9]+")) {
                return null;
            }
        }

        if (end[0].length() != 3 || !isNumber(end[0])) {
            return null;
        }

        if (!end[1].equals("-") && !isNumber(end[1])) {
            return null;
        }

        return start[0];
    }

    private boolean isValidIp(String ip) {
        if (ip.contains(":")) {
            if (!ip.matches("[0-9a-fA-F:.]+")) {
                return false;
            }

            try {
                return InetAddress.getByName(ip) instanceof Inet6Address;
            } catch (UnknownHostException e) {
                return false;
            }
        }

        String[] parts = ip.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !isNumber(part)) {
                return false;
            }

            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }

        return true;
    }

    private boolean isNumber(String value) {
        if (value.isEmpty()) {
            return false;
        }

        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) < '0' || value.charAt(i) > '9') {
                return false;
            }
        }

        return true;
    }
}
