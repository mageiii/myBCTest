import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Test {

    public static void main(String[] args) throws IOException {
        String certFilePath = "/Users/mage/project/bcprov-jdk15on-160/src/main/test/makeStampOrg.cer";
        byte[] certSrc = InputStream2ByteArray(certFilePath);

        byte[] certInfo = getCSPK(certSrc);
//        saveFileWithBytes(certInfo,"/Users/mage/project/gmcertparseTest/","test.cer");

    }
    private static byte[] InputStream2ByteArray(String filePath) throws IOException {

        InputStream in = new FileInputStream(filePath);
        byte[] data = toByteArray(in);
        in.close();

        return data;
    }

    private static byte[] toByteArray(InputStream in) throws IOException {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024 * 4];
        int n = 0;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

/*    public static byte[] getCSPK_new(byte[] csCert)
    {
        InputStream inStream = new ByteArrayInputStream(csCert);
        ASN1Sequence seq = null;
        ASN1InputStream aIn;
        try
        {
            aIn = new ASN1InputStream(inStream);
            seq = (ASN1Sequence)aIn.readObject();
            X509CertificateStructure cert = new X509CertificateStructure(seq);
            cert.getVersion();
//            ASN1Primitive publicKey = cert.getSubjectPublicKeyInfo().getPublicKey();
//            byte[] encodedPublicKey = publicKey.getEncoded();
            byte[] eP = new byte[64];
//            System.arraycopy(encodedPublicKey, 5, eP, 0, eP.length);
            return eP;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }*/
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

    public static void saveFileWithBytes(byte[] bytes, String filePath, String fileName) {
        BufferedOutputStream bos = null;
        FileOutputStream fos = null;
        File file = null;
        try {
            File dir = new File(filePath);
            if (!dir.exists() && dir.isDirectory()) {// 判断文件目录是否存在
                dir.mkdirs();
            }
            file = new File(filePath + "\\" + fileName);
            fos = new FileOutputStream(file);
            bos = new BufferedOutputStream(fos);
            bos.write(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

}
