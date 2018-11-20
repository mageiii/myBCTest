package org.bouncycastle.util.certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.convertor.BitSetConvertor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;

public class PemCertParser extends CertParser{
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private static final String CERTIFICATE = "CERTIFICATE-----";

    public PemCertParser() {
        parseStyle = "PEM";
    }

    @Override
    public CertInfoTem parseCert(byte[] certSrc) {
        if(!isCurParseStyle(certSrc)){
            System.out.println("该cert非" + getCurCertStyle() + "格式！");
            return certInfo;
        }
        try {
            certInfo = X509toCertInfo(
                    pemCert2CertInfo(certSrc)
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
        return certInfo;
    }

    @Override
    public String getCurCertStyle() {
        return parseStyle;
    }

    @Override
    public boolean isCurParseStyle(byte[] certSrc) {
        String certStr = new String(certSrc);
        if (certStr.contains(BEGIN+CERTIFICATE) && certStr.contains(END+CERTIFICATE)){
            return true;
        }
        return false;
    }

    private CertInfoTem X509toCertInfo(X509CertificateStructure x509Cert) throws IOException {
        CertInfoTem CertInfoTem = new CertInfoTem();
        CertInfoTem.setVersion(x509Cert.getVersion());
        CertInfoTem.setSerialNumber(x509Cert.getSerialNumber().toString());
        CertInfoTem.setSubject(x509Cert.getSubject().toString());
        CertInfoTem.setIssuer(x509Cert.getIssuer().toString());
        CertInfoTem.setStartTime(x509Cert.getStartDate());
        CertInfoTem.setEndTime(x509Cert.getEndDate());
        CertInfoTem.setPublicKey(x509Cert.getSubjectPublicKeyInfo().getPublicKeyData().getEncoded());
        CertInfoTem.setSignature(BitSetConvertor.byteArray2BitSet(x509Cert.getSignature().getEncoded()));
        CertInfoTem.setAlgorithm(x509Cert.getSignatureAlgorithm().getAlgorithm().toString());
        return CertInfoTem;
    }

    private X509CertificateStructure pemCert2CertInfo(byte[] certSrcBytes) throws IOException {
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
        }finally {
            rd.close();
            pr.close();
        }
        InputStream inStream = new ByteArrayInputStream(pemCert.getContent());
        ASN1Sequence seq = null;
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
