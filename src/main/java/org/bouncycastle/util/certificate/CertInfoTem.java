package org.bouncycastle.util.certificate;

import org.bouncycastle.asn1.x509.Time;

import java.util.BitSet;

public class CertInfoTem {
    private int version;
    private String serialNumber;
    private String subject;
    private String issuer;
    private Time startTime;
    private Time endTime;
    private BitSet signature;
    private byte[] publicKey;
    private String algorithm;

    public CertInfoTem() {
    }

    public int getVersion() {
        return version;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getsubject() {
        return subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public Time getStartTime() {
        return startTime;
    }

    public Time getEndTime() {
        return endTime;
    }

    public BitSet getSignature() {
        return signature;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setStartTime(Time startTime) {
        this.startTime = startTime;
    }

    public void setEndTime(Time endTime) {
        this.endTime = endTime;
    }

    public void setSignature(BitSet signature) {
        this.signature = signature;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}
