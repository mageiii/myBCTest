import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;

public class Test {

    public static void main(String[] args) throws IOException {
        String certFilePath = "E:\\wk\\myBCTest\\src\\main\\test\\makeStampOrg.cer";
        Reader rd = new FileReader(certFilePath);
        PemReader pr = new PemReader(rd);
        PemObject pemCert =  pr.readPemObject();
        byte[] certInfo = getCSPK(pemCert.getContent());

    }
    public static byte[] getCSPK(byte[] csCert)
    {
        InputStream inStream = new ByteArrayInputStream(csCert);
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try
        {
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            ASN1Integer aserialNumber= cert.getSerialNumber();// 序列号
            String serialNumber=aserialNumber.toString();
            X500Name name= cert.getSubject();// 使用者
            X500Name issuer= cert.getIssuer(); // 颁发者
            Time stime=  cert.getStartDate(); // 有效期
            Time etime=cert.getEndDate();// 到
            DERBitString d=cert.getSignature();
            AlgorithmIdentifier alg= cert.getSignatureAlgorithm();
            ASN1ObjectIdentifier identifier= alg.getAlgorithm();// 签名算法

            SubjectPublicKeyInfo subjectPublicKeyInfo = cert.getSubjectPublicKeyInfo();

            DERBitString publicKeyData = subjectPublicKeyInfo.getPublicKeyData();
            byte[] publicKey = publicKeyData.getEncoded();
            byte[] encodedPublicKey = publicKey;// 公钥
            byte[] eP = new byte[64];
            System.arraycopy(encodedPublicKey, 4, eP, 0, eP.length);
            return eP;
        }
        catch (Exception e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
}
