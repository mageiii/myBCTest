package org.bouncycastle.util.certificate;

public abstract class CertParser {

    protected CertInfoTem certInfo;//转换后的证书信息
    protected String parseStyle = "default";//转换证书类型

    /**
     * 证书转换函数
     * @param certSrc
     * @return
     */
    public CertInfoTem parseCert(byte[] certSrc){
        return null;
    }

    /**
     * 获取当前证书转换类型
     * @return
     */
    public String getCurCertStyle(){
        return parseStyle;
    }

    /**
     * 判断源cert类型与当前parser转换的类型是否一致
     * @param certSrc
     * @return
     */
    public boolean isCurParseStyle(byte[] certSrc){
        return false;
    }
}
