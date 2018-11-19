package org.bouncycastle.util.certificate;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.convertor.BitSetConvertor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.util.BitSet;

/**
 * Created by Administrator on 2018/11/19.
 */
public class PemCert {
    private int version;
    private String serialNumber;
    private String name;
    private String issuer;
    private Time startTime;
    private Time endTime;
    private BitSet signature;
    private byte[] publicKey;
    private String algorithm;
    private X509CertificateStructure cert;

    /**
     * 根据文件解析构建证书
     * @param filePath
     * @param isFilePath
     */
    public PemCert(String filePath,boolean isFilePath) {
        if(isFilePath){
            cert = pemCert2SM2Cert(filePath);
            fillCertParamter(cert);
        }else {
            throw new IllegalArgumentException("格式不正确，请确认Constructor格式");
        }
    }

    /**
     *根据Base64字符串解析构建证书
     * @param certBase64SrcStr
     */
    public PemCert(String certBase64SrcStr) {
        cert = pemCert2SM2CertByPemBase64(certBase64SrcStr);
        fillCertParamter(cert);
    }

    /**
     * 根据byte数组解析构建证书
     * @param certSrc
     */
    public PemCert(byte[] certSrc) {
        cert = pemCert2SM2Cert(certSrc);
        fillCertParamter(cert);
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getVersion() {
        return version;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getName() {
        return name;
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
    private X509CertificateStructure pemCert2SM2Cert(String certFilePath)
    {
        Reader rd = null;
        PemReader pr = null;
        PemObject pemCert = null;
        try {
            rd = new FileReader(certFilePath);
            pr = new PemReader(rd);
            pemCert = pr.readPemObject();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if(!"CERTIFICATE".equals(pemCert.getType())){
            throw new IllegalArgumentException("pem格式文件头不是CERTIFICATE（证书），确认文件是否正确！");
        }
        InputStream inStream = new ByteArrayInputStream(pemCert.getContent());
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try{
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            return cert;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    private X509CertificateStructure pemCert2SM2Cert(byte[] certSrcBytes)
    {
        Reader rd = null;
        PemReader pr = null;
        PemObject pemCert = null;
        try {
            rd = new StringReader(new String(certSrcBytes));
            pr = new PemReader(rd);
            pemCert = pr.readPemObject();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if(!"CERTIFICATE".equals(pemCert.getType())){
            throw new IllegalArgumentException("pem格式文件头不是CERTIFICATE（证书），确认文件是否正确！");
        }
        InputStream inStream = new ByteArrayInputStream(pemCert.getContent());
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try{
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            return cert;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    private X509CertificateStructure pemCert2SM2CertByPemBase64(String certBase64SrcStr)
    {
        Reader rd = null;
        PemReader pr = null;
        PemObject pemCert = null;
        try {
            rd = new StringReader(certBase64SrcStr);
            pr = new PemReader(rd);
            pemCert = pr.readPemObject();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if(!"CERTIFICATE".equals(pemCert.getType())){
            throw new IllegalArgumentException("pem格式文件头不是CERTIFICATE（证书），确认文件是否正确！");
        }
        InputStream inStream = new ByteArrayInputStream(pemCert.getContent());
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try{
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            return cert;
        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    private void fillCertParamter(X509CertificateStructure cert){
        version = cert.getVersion();
        serialNumber = cert.getSerialNumber().toString();
        name = cert.getSubject().toString();
        issuer = cert.getIssuer().toString();
        startTime = cert.getStartDate();
        endTime = cert.getEndDate();
        try {
            signature = BitSetConvertor.byteArray2BitSet(cert.getSignature().getEncoded());
            publicKey = cert.getSubjectPublicKeyInfo().getPublicKeyData().getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
        }
        algorithm = cert.getSignatureAlgorithm().getAlgorithm().toString();
    }
}
