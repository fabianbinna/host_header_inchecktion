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
        "Host: www.example.com<br/>Host: [PAYLOAD]"),

    DUPLICATE_BEFORE_HOST("Duplicate Host Header Before Host Header",
        HostHeaderInjection::generateDuplicatedHostHeaderBefore,
        "Host: [PAYLOAD]<br/>Host: www.example.com"),

    INDENTED_AFTER_HOST("Indented Host Header After Host Header",
        HostHeaderInjection::generateIndentedHostHeaderAfter,
        "Host: www.example.com<br/> Host: [PAYLOAD]"),

    INDENTED_BEFORE_HOST("Indented Host Header Before Host Header",
        HostHeaderInjection::generateIndentedHostHeaderBefore,
        " Host: [PAYLOAD]<br/>Host: www.example.com"),

    X_HOST("X-Host Header",
        HostHeaderInjection::generateXHostHostHeader,
        "Host: www.example.com<br/>X-Host: [PAYLOAD]"),

    X_FORWARDED_HOST("X-Forwarded-Host Header",
        HostHeaderInjection::generateXForwardedHostHostHeader,
        "Host: www.example.com<br/>X-Forwarded-Host: [PAYLOAD]"),

    X_FORWARDED_SERVER("X-Forwarded-Server Header",
        HostHeaderInjection::generateXForwardedServerHostHeader,
        "Host: www.example.com<br/>X-Forwarded-Server: [PAYLOAD]"),

    X_HTTP_HOST_OVERRIDE("X-HTTP-Host-Override Header",
        HostHeaderInjection::generateXHTTPHostOverrideHostHeader,
        "Host: www.example.com<br/>X-HTTP-Host-Override: [PAYLOAD]"),

    FORWARDED("Forwarded Header",
        HostHeaderInjection::generateForwardedHostHeader,
        "Host: www.example.com<br/>Forwarded: [PAYLOAD]"),

    X_ORIGINATING_IP("X-Originating-IP Header",
        HostHeaderInjection::generateXOriginatingIPHostHeader,
        "Host: www.example.com<br/>X-Originating-IP: [PAYLOAD]"),

    X_FORWARDED_FOR("X-Forwarded-For Header",
        HostHeaderInjection::generateXForwardedForHostHeader,
        "Host: www.example.com<br/>X-Forwarded-For: [PAYLOAD]"),

    X_FORWARDED("X-Forwarded",
        HostHeaderInjection::generateXForwardedHostHeader,
        "Host: www.example.com<br/>X-Forwarded: [PAYLOAD]"),

    FORWARDED_FOR("Forwarded-For",
        HostHeaderInjection::generateForwardedForHostHeader,
        "Host: www.example.com<br/>Forwarded-For: [PAYLOAD]"),

    X_REMOTE_IP("X-Remote-IP",
        HostHeaderInjection::generateXRemoteIPHostHeader,
        "Host: www.example.com<br/>X-Remote-IP: [PAYLOAD]"),

    X_REMOTE_ADDR("X-Remote-Addr",
        HostHeaderInjection::generateXRemoteAddrHostHeader,
        "Host: www.example.com<br/>X-Remote-Addr: [PAYLOAD]"),

    X_PROXY_USER_IP("X-ProxyUser-Ip",
        HostHeaderInjection::generateXProxyUserIpHostHeader,
        "Host: www.example.com<br/>X-ProxyUser-Ip: [PAYLOAD]"),

    X_ORIGINAL_URL("X-Original-URL",
        HostHeaderInjection::generateXOriginalURLHostHeader,
        "Host: www.example.com<br/>X-Original-URL: [PAYLOAD]"),

    CLIENT_IP("Client-IP",
        HostHeaderInjection::generateClientIPHostHeader,
        "Host: www.example.com<br/>Client-IP: [PAYLOAD]"),

    TRUE_CLIENT_IP("True-Client-IP",
        HostHeaderInjection::generateTrueClientIPHostHeader,
        "Host: www.example.com<br/>True-Client-IP: [PAYLOAD]"),

    CLUSTER_CLIENT_IP("Cluster-Client-IP",
        HostHeaderInjection::generateClusterClientIPHostHeader,
        "Host: www.example.com<br/>Cluster-Client-IP: [PAYLOAD]"),

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
        "GET https://[PAYLOAD]/ HTTP/1.1<br/>Host: www.example.com"),

    MALFORMED_REQUEST_LINE("Malformed Request Line",
        HostHeaderInjection::generateMalformedRequestLine,
        "GET @[PAYLOAD]/example HTTP/1.1<br/>Host: www.example.com");

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

    private static List<String> generateXForwardedHostHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Forwarded-Host: " + payload);
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

    private static List<String> generateXOriginatingIPHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Originating-IP: " + payload);
    }

    private static List<String> generateXForwardedForHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Forwarded-For: " + payload);
    }

    private static List<String> generateXForwardedHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Forwarded: " + payload);
    }

    private static List<String> generateForwardedForHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "Forwarded-For: " + payload);
    }

    private static List<String> generateXRemoteIPHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Remote-IP: " + payload);
    }

    private static List<String> generateXRemoteAddrHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Remote-Addr: " + payload);
    }

    private static List<String> generateXProxyUserIpHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-ProxyUser-Ip: " + payload);
    }

    private static List<String> generateXOriginalURLHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "X-Original-URL: " + payload);
    }

    private static List<String> generateClientIPHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "Client-IP: " + payload);
    }

    private static List<String> generateTrueClientIPHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "True-Client-IP: " + payload);
    }

    private static List<String> generateClusterClientIPHostHeader(String payload, List<String> headers) {
        return addHeaderAfterHostHeader(headers, "Cluster-Client-IP: " + payload);
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
