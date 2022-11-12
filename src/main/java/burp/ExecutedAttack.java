package burp;

record ExecutedAttack(HostHeaderInjection hostHeaderInjection, String payload, IHttpRequestResponse originalRequestResponse, IHttpRequestResponse attackRequestResponse) {

}
