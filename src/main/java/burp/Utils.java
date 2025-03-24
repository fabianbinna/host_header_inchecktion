package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum Utils {
    ;

    static List<String> rewriteUrl(List<String> headers, BiFunction<String, String, String> rewrite) {
        var modifiedHeaders = new ArrayList<String>();
        var url = headers.get(0);
        String hostHeader = "";
        for (var header : headers) {
            if (header.startsWith("Host:")) {
                hostHeader = header;
            }
            modifiedHeaders.add(header);
        }
        modifiedHeaders.set(0, rewrite.apply(url, hostHeader));
        return modifiedHeaders;
    }

    static List<String> rewriteHostHeader(List<String> headers, Function<String, String> rewrite) {
        var modifiedHeaders = new ArrayList<String>();
        for (var header : headers) {
            if (header.startsWith("Host:")) {
                modifiedHeaders.add("Host: " + rewrite.apply(header.split(":")[1].trim()));
            } else {
                modifiedHeaders.add(header);
            }
        }
        return modifiedHeaders;
    }

    static List<String> addHeaderAfterHostHeader(List<String> headers, String newHeader) {
        var modifiedHeaders = new ArrayList<String>();
        for (var header : headers) {
            if (header.startsWith("Host:")) {
                modifiedHeaders.add(header);
                modifiedHeaders.add(newHeader);
            } else {
                modifiedHeaders.add(header);
            }
        }
        return modifiedHeaders;
    }

    static List<String> addHeaderBeforeHostHeader(List<String> headers, String newHeader) {
        var modifiedHeaders = new ArrayList<String>();
        for (var header : headers) {
            if (header.startsWith("Host:")) {
                modifiedHeaders.add(newHeader);
                modifiedHeaders.add(header);
            } else {
                modifiedHeaders.add(header);
            }
        }
        return modifiedHeaders;
    }

    static List<String> addCacheBuster(List<String> headers) {
        return Utils.rewriteUrl(headers, (url, hostHeader) -> {
            var urlParts = url.split("\s");
            String cacheBuster = (urlParts[1].contains("?") ? "&" : "?") + "cb=" + UUID.randomUUID();
            return String.format("%s\s%s\s%s", urlParts[0], urlParts[1] + cacheBuster, urlParts[2]);
        });
    }

    static List<String> addCacheControl(List<String> headers) {
        var modifiedHeaders = new ArrayList<String>();
        for (var header : headers) {
            if (!header.startsWith("Cache-Control:")) {
                modifiedHeaders.add(header);
            }
        }
        modifiedHeaders.add("Cache-Control: no-cache");
        return modifiedHeaders;
    }

    static List<int[]> getMatches(byte[] response, byte[] match, IExtensionHelpers helpers) {
        List<int[]> matches = new ArrayList<>();

        int start = 0;
        while (start < response.length) {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1) {
                break;
            }
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    static String removeHeader(String httpMessage) {
        return Arrays.stream(httpMessage.split("\r\n\r\n"))
            .skip(1)
            .collect(Collectors.joining("\r\n\r\n"));
    }

}
