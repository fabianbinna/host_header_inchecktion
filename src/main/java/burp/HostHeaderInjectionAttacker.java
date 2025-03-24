package burp;

import org.apache.commons.text.similarity.JaroWinklerDistance;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static burp.Utils.*;

final class HostHeaderInjectionAttacker {

    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IBurpCollaboratorClientContext collaboratorClientContext;
    private final JaroWinklerDistance jaroWinklerDistance;

    HostHeaderInjectionAttacker(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.collaboratorClientContext = callbacks.createBurpCollaboratorClientContext();
        this.jaroWinklerDistance = new JaroWinklerDistance();
    }

    List<IScanIssue> attackWithCollaborator(IHttpRequestResponse baseRequestResponse) {
        var executedAttacks = attackWithPayload(baseRequestResponse,
                () -> collaboratorClientContext.generatePayload(true));
        var interactions = collaboratorClientContext.fetchAllCollaboratorInteractions();
        return executedAttacks.stream()
                .filter(executedAttack -> isInteracted(interactions, executedAttack))
                .map(this::generateSSRFIssue)
                .collect(Collectors.toList());
    }

    List<IScanIssue> attackWithLocalhost(IHttpRequestResponse baseRequestResponse) {
        return attackWithPayload(baseRequestResponse, () -> "localhost").stream()
                .filter(executedAttack -> isStatusCode200(executedAttack.attackRequestResponse()))
                .filter(this::areResponsesSimilar)
                .map(this::generateAuthenticationBypassIssue)
                .collect(Collectors.toList());
    }

    List<IScanIssue> attackWithCanary(IHttpRequestResponse baseRequestResponse) {
        return attackWithPayload(baseRequestResponse, () -> String.valueOf(UUID.randomUUID())).stream()
                .filter(this::isPayloadReflected)
                .map(this::generateReflectionIssue)
                .collect(Collectors.toList());
    }

    private List<ExecutedAttack> attackWithPayload(
            IHttpRequestResponse originalRequestResponse,
            Supplier<String> payloadSupplier) {
        var requestInfo = this.helpers.analyzeRequest(originalRequestResponse);
        var request = originalRequestResponse.getRequest();
        var body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        var headers = requestInfo.getHeaders();

        List<ExecutedAttack> executedAttacks = new ArrayList<>();
        for(var attack : HostHeaderInjection.values()) {
            String payload = payloadSupplier.get();
            var patchedHeader = attack.patchHeader(payload, headers);
            patchedHeader = addCacheBuster(patchedHeader);
            patchedHeader = addCacheControl(patchedHeader);
            byte[] rawMessage = this.helpers.buildHttpMessage(patchedHeader, body);
            IHttpRequestResponse attackRequestResponse = callbacks.makeHttpRequest(originalRequestResponse.getHttpService(), rawMessage);
            executedAttacks.add(new ExecutedAttack(attack, payload, originalRequestResponse, attackRequestResponse));
        }
        return executedAttacks;
    }

    private static boolean isInteracted(
            List<IBurpCollaboratorInteraction> interactions,
            ExecutedAttack executedAttack) {
        var payload = executedAttack.payload();
        return interactions.stream()
                .anyMatch(interaction -> payload.startsWith(interaction.getProperty("interaction_id")));
    }

    private boolean isStatusCode200(IHttpRequestResponse baseRequestResponse) {
        var response = baseRequestResponse.getResponse();
        if(response == null) {
            return false;
        }
        return this.helpers.analyzeResponse(response).getStatusCode() / 100 == 2;
    }

    private boolean areResponsesSimilar(ExecutedAttack executedAttack) {
        var originalResponse = executedAttack.originalRequestResponse().getResponse();
        var attackResponse = executedAttack.attackRequestResponse().getResponse();
        if(originalResponse == null || attackResponse == null) {
            return false;
        }

        var originalResponseString = new String(originalResponse, StandardCharsets.UTF_8);
        var attackResponseString = new String(attackResponse, StandardCharsets.UTF_8);

        double distance = this.jaroWinklerDistance.apply(
            removeHeader(originalResponseString),
            removeHeader(attackResponseString));

        return 0.05 < distance && distance < 0.1;
    }

    private boolean isPayloadReflected(ExecutedAttack executedAttack) {
        var rawResponse = executedAttack.attackRequestResponse().getResponse();
        if(rawResponse == null) {
            return false;
        }

        var response = this.helpers.analyzeResponse(rawResponse);
        var matches = getMatches(rawResponse, executedAttack.payload().getBytes(StandardCharsets.UTF_8),
                this.helpers);
        return matches.size() > 0 && response.getStatusCode() / 100 == 2;
    }

    private IScanIssue generateSSRFIssue(ExecutedAttack executedAttack) {
        var requestResponse = executedAttack.attackRequestResponse();
        var payload = executedAttack.payload();
        var request = requestResponse.getRequest();
        var requestMatches = getMatches(request, payload.getBytes(StandardCharsets.UTF_8), this.helpers);

        return HostHeaderInjectionScanIssue.createSSRFIssue(
                requestResponse.getHttpService(),
                this.helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMatches, null) },
                executedAttack.hostHeaderInjection());
    }

    private IScanIssue generateAuthenticationBypassIssue(ExecutedAttack executedAttack) {
        var requestResponse = executedAttack.attackRequestResponse();
        var payload = executedAttack.payload();
        var request = requestResponse.getRequest();
        var requestMatches = getMatches(request, payload.getBytes(StandardCharsets.UTF_8), this.helpers);

        return HostHeaderInjectionScanIssue.createAuthenticationBypassIssue(
                requestResponse.getHttpService(),
                this.helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMatches, null) },
                executedAttack.hostHeaderInjection());
    }

    private IScanIssue generateReflectionIssue(ExecutedAttack executedAttack) {
        var requestResponse = executedAttack.attackRequestResponse();
        var payload = executedAttack.payload();
        var request = requestResponse.getRequest();
        var response = requestResponse.getResponse();
        var requestMatches = getMatches(request, payload.getBytes(StandardCharsets.UTF_8), this.helpers);
        var responseMatches = getMatches(response, payload.getBytes(StandardCharsets.UTF_8), this.helpers);

        return HostHeaderInjectionScanIssue.createReflectionIssue(
                requestResponse.getHttpService(),
                this.helpers.analyzeRequest(requestResponse).getUrl(),
                new IHttpRequestResponse[] { callbacks.applyMarkers(requestResponse, requestMatches, responseMatches) },
                executedAttack.hostHeaderInjection());
    }

}
