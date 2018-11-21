package org.bouncycastle.util.certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.convertor.BitSetConvertor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;

public class DerCertParser extends CertParser {
    public DerCertParser() {
        parseStyle = "DER";
    }

    @Override
    public CertInfoTem parseCert(byte[] certSrc) {
        if(!isCurParseStyle(certSrc)){
            System.out.println("该cert非" + getCurCertStyle() + "格式！");
            return certInfo;
        }
        try {
            certInfo = X509toCertInfo(
                    derCert2X509(certSrc)
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
        return certInfo;
    }

    private X509CertificateStructure derCert2X509(byte[] certSrcBytes) throws IOException {
        X509CertificateStructure cert = getX509CertificateStructure(certSrcBytes);
        if (cert != null) return cert;
        return null;
    }
}
