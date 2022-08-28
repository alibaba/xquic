package nativejni;

import android.os.Build;

public class SendConfig {

    String serverAddress = null;
    int serverPort = 8443;
    int requestParal = 1;
    int reqtesMax = 1;
    int bodySize = 1024 * 1024;
    int forceCertVerification = 0;
    String url = null;

    int pacingOn = 0;
    int force1RTT = 0;
    int ipv6 = 0;
    int noCrypt = 0;

    String CCType = null;
    String requestType = null;

    public static class Builder {
        private SendConfig sConfig = new SendConfig();

        public Builder serverAddress(String serverAddr) {
            sConfig.serverAddress = serverAddr;
            return this;
        }

        public Builder serverPort(int serverPort) {
            sConfig.serverPort = serverPort;
            return this;
        }

        public Builder requestParallel(int reqParal) {
            sConfig.requestParal = reqParal;
            return this;
        }

        public Builder requestMax(int reqMax) {
            sConfig.reqtesMax = reqMax;
            return this;
        }

        public Builder bodySizeToSend(int bodySize2Send) {
            sConfig.bodySize = bodySize2Send;
            return this;
        }

        public Builder forceCertVerification(int verifyCertAllowSelfSign) {
            sConfig.forceCertVerification = verifyCertAllowSelfSign;
            return this;
        }

        public Builder Url(String url) {
            sConfig.url = url;
            return this;
        }

        public Builder pacingOn(int pacingOn) {
            sConfig.pacingOn = pacingOn;
            return this;
        }

        public Builder force1RTT(int force1RTT) {
            sConfig.force1RTT = force1RTT;
            return this;
        }

        public Builder ipv6(int ipv6) {
            sConfig.ipv6 = ipv6;
            return this;
        }

        public Builder noCrypt(int noCrypt) {
            sConfig.noCrypt = noCrypt;
            return this;
        }

        public Builder CCType(String CCType) {
            sConfig.CCType = CCType;
            return this;
        }

        public Builder requestType(String requestType) {
            sConfig.requestType = requestType;
            return this;
        }

        public SendConfig build() {
            return sConfig;
        }
    }
}
