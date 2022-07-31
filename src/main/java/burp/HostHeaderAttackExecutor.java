package burp;

import javax.swing.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import static burp.HostHeaderAttackConfig.AttackType.CANARY;
import static burp.HostHeaderUtils.addCacheBuster;

class HostHeaderAttackExecutor {

    private static final Executor executor = Executors.newSingleThreadExecutor();

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;

    HostHeaderAttackExecutor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    void execute(IHttpRequestResponse[] originalMessages) {
        HostHeaderAttackConfigDialog hostHeaderAttackConfigDialog = new HostHeaderAttackConfigDialog();
        int selectedOption = hostHeaderAttackConfigDialog.showDialog();
        if(selectedOption != JOptionPane.OK_OPTION) {
            return;
        }
        var attackConfig = hostHeaderAttackConfigDialog.getAttackConfig();
        
        for(var originalMessage : originalMessages) {
            executor.execute(() -> {
                var request = this.helpers.analyzeRequest(originalMessage);
                var headers = request.getHeaders();
                var rawRequest = originalMessage.getRequest();
                var rawBody = Arrays.copyOfRange(rawRequest, request.getBodyOffset(), rawRequest.length);

                for(var attack : attackConfig.getAttacks()) {
                    List<String> patchedHeaders = attack.patchHeader(attackConfig.getPayload(), headers);
                    if(attackConfig.useCacheBuster()) {
                        patchedHeaders = addCacheBuster(patchedHeaders);
                    }

                    var requestResponse = sendRequest(patchedHeaders, rawBody, originalMessage);
                    if(attackConfig.getAttackType() == CANARY) {
                        reportReflections(requestResponse, attackConfig.getPayload());
                    }
                }
            });
        }
    }

    private IHttpRequestResponse sendRequest(List<String> headers, byte[] rawBody, IHttpRequestResponse message) {
        byte[] rawMessage = this.helpers.buildHttpMessage(headers, rawBody);
        return callbacks.makeHttpRequest(message.getHttpService(), rawMessage);
    }

    private void reportReflections(IHttpRequestResponse requestResponse, String payload) {
        byte[] request = requestResponse.getRequest();
        byte[] response = requestResponse.getResponse();
        if(request == null || response == null) {
            return;
        }
        var requestMatches = getMatches(request, payload.getBytes(StandardCharsets.UTF_8));
        var responseMatches = getMatches(response, payload.getBytes(StandardCharsets.UTF_8));
        if(responseMatches.size() > 0) {
            HostHeaderScanIssue hostHeaderScanIssue = HostHeaderScanIssue.createDefaultIssue(
                    requestResponse.getHttpService(),
                    this.helpers.analyzeRequest(requestResponse).getUrl(),
                    new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMatches, responseMatches) });
            callbacks.addScanIssue(hostHeaderScanIssue);
        }
    }

    private List<int[]> getMatches(byte[] response, byte[] match) {
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

}
