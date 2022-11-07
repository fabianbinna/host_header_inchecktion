package burp;

import java.net.URL;

public class HostHeaderInjectionScanIssue implements IScanIssue {

    private final IHttpService httpService;
    private final URL url;
    private final IHttpRequestResponse[] httpMessages;
    private final String name;
    private final String detail;
    private final String severity;

    private HostHeaderInjectionScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    public static HostHeaderInjectionScanIssue createDefaultIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages) {
        return new HostHeaderInjectionScanIssue(
                httpService,
                url,
                httpMessages,
                "Host Header Injection",
                "The host header payload was probably reflected.",
                "Medium");
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
        return "Firm";
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
        return null;
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
