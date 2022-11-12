package burp;

import java.net.URL;

public class HostHeaderInjectionScanIssue implements IScanIssue {

    private final IHttpService httpService;
    private final URL url;
    private final IHttpRequestResponse[] httpMessages;
    private final String name;
    private final String detail;
    private final String remediation;
    private final String severity;
    private final String confidence;

    private HostHeaderInjectionScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String remediation,
            String severity,
            String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.remediation = remediation;
        this.severity = severity;
        this.confidence = confidence;
    }

    public static HostHeaderInjectionScanIssue createSSRFIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            HostHeaderInjection hostHeaderInjection) {
        return new HostHeaderInjectionScanIssue(
                httpService,
                url,
                httpMessages,
                "SSRF via Host Header Injection: %s".formatted(hostHeaderInjection.title()),
                """
                        The injected host header triggered a server-side request that could be received by
                        the burp collaborator endpoint. It seems to be possible to force the server to connect
                        to an arbitrary host.
                        <br/><br/>
                        The payload was injected at the following position:<br/>
                        %s
                        """.formatted(hostHeaderInjection.description()),
                """
                        Validate the host header properly. Check the host header against a whitelist. The simplest 
                        approach to remediate is to avoid using host header in server-side code.<br/>
                        <br/>
                        <b>Resources:</b>
                        <ul>
                        <li>https://portswigger.net/web-security/host-header#how-to-prevent-http-host-header-attacks</li>
                        <li>https://portswigger.net/web-security/host-header/exploiting#exploiting-classic-server-side-vulnerabilities</li>
                        </ul>
                        """,
                "Medium",
                "Certain");
    }

    public static HostHeaderInjectionScanIssue createAuthenticationBypassIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            HostHeaderInjection hostHeaderInjection) {
        return new HostHeaderInjectionScanIssue(
                httpService,
                url,
                httpMessages,
                "Authentication Bypass via Host Header Injection: %s".formatted(hostHeaderInjection.title()),
                """
                        The payload "localhost" injected into the host header resulted in a response
                        with status code 200. The response body is different to the body of the original request.
                        It could be possible to access restricted functions that are only available from localhost.
                        <br/><br/>
                        The payload was injected at the following position:<br/>
                        %s
                        """.formatted(hostHeaderInjection.description()),
                """
                        Validate the host header properly. Check the host header against a whitelist. The simplest
                        approach to remediate is to avoid using host header in server-side code.<br/>
                        <br/>
                        <b>Resources:</b>
                        <ul>
                        <li>https://portswigger.net/web-security/host-header#how-to-prevent-http-host-header-attacks</li>
                        <li>https://portswigger.net/web-security/host-header/exploiting#exploiting-classic-server-side-vulnerabilities</li>
                        </ul>
                        """,
                "Low",
                "Tentative");
    }

    public static HostHeaderInjectionScanIssue createReflectionIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            HostHeaderInjection hostHeaderInjection) {
        return new HostHeaderInjectionScanIssue(
                httpService,
                url,
                httpMessages,
                "Web Cache Poisoning via Host Header Injection: %s".formatted(hostHeaderInjection.title()),
                """
                        The host header payload was reflected. This can lead to web cache poisoning.<br/><br/>
                        The payload was injected at the following position:<br/>
                        %s
                        """.formatted(hostHeaderInjection.description()),
                """
                        Validate the host header properly. Check the host header against a whitelist. The simplest
                        approach to remediate is to avoid using host header in server-side code.<br/>
                        <br/>
                        <b>Resources:</b>
                        <ul>
                        <li>https://portswigger.net/web-security/host-header#how-to-prevent-http-host-header-attacks</li>
                        <li>https://portswigger.net/web-security/host-header/exploiting#exploiting-classic-server-side-vulnerabilities</li>
                        </ul>
                        """,
                "Low",
                "Tentative");
    }

    @Override
    public URL getUrl() {
        return this.url;
    }

    @Override
    public String getIssueName() {
        return this.name;
    }

    @Override
    public int getIssueType() {
        return 0;
    }

    @Override
    public String getSeverity() {
        return this.severity;
    }

    @Override
    public String getConfidence() {
        return this.confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return this.detail;
    }

    @Override
    public String getRemediationDetail() {
        return this.remediation;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
