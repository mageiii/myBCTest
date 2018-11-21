package org.bouncycastle.util.certificate;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.convertor.BitSetConvertor;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;

public class PemCertParser extends CertParser{


    public PemCertParser() {
        parseStyle = "PEM";
    }

    @Override
    public CertInfoTem parseCert(byte[] certSrc) {
        if(!isPemParseStyle(certSrc)){
            System.out.println("该cert非" + getCurCertStyle() + "格式！");
            return certInfo;
        }
        try {
            certInfo = X509toCertInfo(
                    pemCert2X509(certSrc)
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
        return certInfo;
    }

    private X509CertificateStructure pemCert2X509(byte[] certSrcBytes) throws IOException {
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
        X509CertificateStructure cert = DerCertParser.getX509CertificateStructure(pemCert.getContent());
        if (cert != null) return cert;
        return null;
    }

}
