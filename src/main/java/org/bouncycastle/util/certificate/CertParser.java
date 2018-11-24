package org.bouncycastle.util.certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.convertor.BitSetConvertor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public abstract class CertParser {

    protected CertInfoTem certInfo = new CertInfoTem();//转换后的证书信息
    protected  static String parseStyle = "default";//转换证书类型
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private static final String CERTIFICATE = "CERTIFICATE-----";
    public CertParser() {}
    /**
     * 证书转换函数
     * @param certSrc
     * @return
     */
    public CertInfoTem parseCert(byte[] certSrc) throws Exception {
        return null;
    }

    /**
     * 判断源cert类型是否PEM，非PEM即DER
     * @param certSrc
     * @return
     */
    public static boolean isPemParseStyle(byte[] certSrc) throws Exception {
        if (certSrc == null){
            throw new Exception("certSrc为null");
        }
        String certStr = new String(certSrc);
        if (certStr.contains(BEGIN+CERTIFICATE) && certStr.contains(END+CERTIFICATE)){
            return true;
        }
        return false;
    }


    protected CertInfoTem X509toCertInfo(X509CertificateStructure x509Cert) throws IOException {
        return getCertInfoTem(x509Cert);
    }

    /**
     * 获取当前证书转换类型
     * @return
     */
    public static String getCurCertStyle(){
        return parseStyle;
    }

    protected static CertInfoTem getCertInfoTem(X509CertificateStructure x509Cert) throws IOException {
        CertInfoTem CertInfoTem = new CertInfoTem();
        CertInfoTem.setVersion(x509Cert.getVersion());
        CertInfoTem.setSerialNumber(x509Cert.getSerialNumber().toString());
        CertInfoTem.setSubject(x509Cert.getSubject().toString());
        CertInfoTem.setIssuer(x509Cert.getIssuer().toString());
        CertInfoTem.setStartTime(x509Cert.getStartDate());
        CertInfoTem.setEndTime(x509Cert.getEndDate());
        CertInfoTem.setPublicKey(x509Cert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        CertInfoTem.setSignature(BitSetConvertor.byteArray2BitSet(x509Cert.getSignature().getBytes()));
        CertInfoTem.setAlgorithm(x509Cert.getSignatureAlgorithm().getAlgorithm().toString());
        return CertInfoTem;
    }
    protected static X509CertificateStructure getX509CertificateStructure(byte[] certBytes) throws IOException {
        ASN1Sequence seq;
        InputStream inStream = new ByteArrayInputStream(certBytes);
        ASN1InputStream aIn = new ASN1InputStream(inStream);
        try{
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            return cert;
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            inStream.close();
            aIn.close();
        }
        return null;
    }
}
