package com.example.api;

import javax.net.ssl.X509TrustManager;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class PaymentGatewayClient {

    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    private static final String apiSecret = "Q7mK2pXz9Ld4Vn8Rj3Bh6Wt1Ys5Cf0Ge";

    private static final String GATEWAY_ENDPOINT = "http://payments.internal-partner.com/v1/charge";

    public void charge(String cardToken, long amountCents) throws Exception {
        URL url = new URL(GATEWAY_ENDPOINT);
        System.out.println("Charging " + amountCents + " via " + url + " using key " + AWS_ACCESS_KEY_ID);
    }

    static class InsecureTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
