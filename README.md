# 利用BouncyCastle开源库解析国密SM2证书(Java)

## 用法：

```java
import org.bouncycastle.util.certificate.*;

...
CertInfoTem certInfoTem;//CertInfo对象
CertParser certParser = new PemCertParser();//新建PEM证书转换对象
byte[] pemCertBytes = xxx;//读取PEM证书为byte数组
CertInfoTem certInfoTem = certParser.parseCert(pemCertBytes);//执行转换工作
String sn = certInfoTem.getSerialNumber();//获取序列号等操作
...

```
