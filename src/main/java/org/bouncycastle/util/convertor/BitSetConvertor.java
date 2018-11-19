package org.bouncycastle.util.convertor;

import java.util.Arrays;
import java.util.BitSet;

/**
 * Created by Administrator on 2018/11/19.
 */
public class BitSetConvertor {
    public static byte[] bitSet2ByteArray(BitSet bitSet) {
        byte[] bytes = new byte[bitSet.size() / 8];
        for (int i = 0; i < bitSet.size(); i++) {
            int index = i / 8;
            int offset = 7 - i % 8;
            bytes[index] |= (bitSet.get(i) ? 1 : 0) << offset;
        }
        return bytes;
    }

    public static BitSet byteArray2BitSet(byte[] bytes) {
        BitSet bitSet = new BitSet(bytes.length * 8);
        int index = 0;
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 7; j >= 0; j--) {
                bitSet.set(index++, (bytes[i] & (1 << j)) >> j == 1 ? true
                        : false);
            }
        }
        return bitSet;
    }

    public static void main(String[] args) {
        BitSet bitSet = new BitSet();
        bitSet.set(0, true);
        bitSet.set(10, true);
        //将BitSet对象转成byte数组
        byte[] bytes = bitSet2ByteArray(bitSet);
        System.out.println(Arrays.toString(bytes));

        //在将byte数组转回来
        bitSet = byteArray2BitSet(bytes);
        System.out.println(bitSet.get(0));
        System.out.println(bitSet.get(10));
    }
}
