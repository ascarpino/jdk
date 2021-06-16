/*
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @summary Verify the output buffer does not contain data on a tag mismatch
 * exception
  */

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.HexFormat;

public class GCMTagMismatch {

    final static HexFormat hex = HexFormat.of();
    final static SecretKey key = new SecretKeySpec(
        hex.parseHex("141f1ce91989b07e7eb6ae1dbd81ea5e"), "AES");
    final static byte[] iv = hex.parseHex(
        "49451da24bd6074509d3cebc2c0394c972e6934b45a1d91f3ce1d3ca69e19" +
            "4aa1958a7c21b6f21d530ce6d2cc5256a3f846b6f9d2f38df0102c4791e5" +
            "7df038f6e69085646007df999751e248e06c47245f4cd3b8004585a7470d" +
            "ee1690e9d2d63169a58d243c0b57b3e5b4a481a3e4e8c60007094ef3adea" +
            "2e8f05dd3a1396f");
    final static byte[] pt = hex.parseHex(
        "d384305af2388699aa302f510913fed0f2cb63ba42efa8c5c9de2922a2ec" +
            "2fe87719dadf1eb0aef212b51e74c9c5b934104a43");
    final static byte[] aad = hex.parseHex(
        "630cf18a91cc5a6481ac9eefd65c24b1a3c93396bd7294d6b8ba3239517" +
            "27666c947a21894a079ef061ee159c05beeb4");
    final static byte[] ct = hex.parseHex(
        "f4c34e5fbe74c0297313268296cd561d59ccc95bbfcdfcdc71b0097dbd83" +
            "240446b28dc088abd42b0fc687f208190ff24c0548");
    // correct tag is:  dbb93bbb56d0439cd09f620a57687f5d
    final static byte[] tag = hex.parseHex("dbb93bbb56d0439cd09f620a57687f00");

    Cipher c;
    byte[] in, out;
    ByteBuffer src, dst;

    GCMTagMismatch() throws Exception {
        c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key,
            new GCMParameterSpec(tag.length * 8, iv));
        c.updateAAD(aad);
        out = new byte[pt.length];
        in = new byte[ct.length + tag.length];
        System.arraycopy(ct, 0, in, 0, ct.length);
        System.arraycopy(tag, 0, in, ct.length, tag.length);
    }

    // Put data in heap bytebuffers
    GCMTagMismatch heap() {
        src = ByteBuffer.wrap(ct);
        dst = ByteBuffer.allocate(pt.length);
        return this;
    }

    // Put data into direct bytebuffers
    GCMTagMismatch direct() {
        src = ByteBuffer.allocateDirect(ct.length);
        src.put(ct);
        src.flip();
        dst = ByteBuffer.allocateDirect(pt.length);
        return this;
    }

    // decrypt data
    GCMTagMismatch decrypt() throws Exception {
        try {
            if (src != null) {
                c.doFinal(src, dst);
            } else {
                c.doFinal(in, 0, in.length, out, 0);
            }
        } catch (AEADBadTagException e) {
            return this;
        }
        throw new Exception("Decryption did not fail with a tag mismatch");
    }

    // Verify the output is zeroed
    void check() throws Exception {
        byte[] o;

        if (dst != null) {
            o = new byte[dst.remaining()];
            dst.get(o);
        } else {
            o = out;
        }

        int i = 0;
        while (i < o.length) {
            if (o[i++] != 0) {
                throw new Exception("Non-zeroed buffer found");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        new GCMTagMismatch().decrypt().check();
        new GCMTagMismatch().heap().decrypt().check();
        new GCMTagMismatch().direct().decrypt().check();
    }
}
