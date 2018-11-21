# 1.数字证书科普

	    数字证书由权威机构——CA机构，又称为证书授权（Certificate Authority）中心发行。
	    现阶段多为X.509格式证书，X.509是ITU-T标准化部门基于他们之前的ASN.1定义的一套证书标准。之前有X.500。
编码方式有两种：DER编码 PEM编码

* DER     R用于二进制DER编码的证书。
* PEM    PEM用于ASCII(Base64)编码的各种X.509 v3 证书。PEM证书文件开始由一行"----- BEGIN **CERTIFICATE** -----"开始，由"----- END **CERTIFICATE** -----"结束。
*注：扩展名不一定为.pem 或.der.。也有.cer  .crt*
> der类型的不用在编码解码，直接就是二进制的数据可以直接使用；
pem类型的数据要根据base64编码解码后，得到的数据需要进行增加或裁剪特殊字符-、\n、\r、begin信息、end信息等。


# 2.代码用法：

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

资源地址：[github](https://github.com/tinerue/myBCTest.git)

