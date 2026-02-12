/*
 * Copyright (c) 2018, 2026, Oracle and/or its affiliates. All rights reserved.
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
 * @bug 8164879 8300285
 * @library ../../
 *          /test/lib
 *          /javax/net/ssl/templates
 * @summary Verify AEAD TLS cipher suite limits set in the jdk.tls.keyLimits
 * property
 * start a new handshake sequence to renegotiate the symmetric key with an
 * SSLSocket connection.  This test verifies the handshake method was called
 * via debugging info.  It does not verify the renegotiation was successful
 * as that is very hard.
 *
 * @run main KeyUpdateOnce 0 server TLS_AES_256_GCM_SHA384
 *
 */

/*
 * This test runs in another process so we can monitor the debug
 * results.  The OutputAnalyzer must see correct debug output to return a
 * success.
 */

import jdk.test.lib.Utils;
import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSocket;
import java.io.File;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class KeyUpdateOnce extends SSLContextTemplate{
        SSLEngine eng;
        static ByteBuffer cTos;
        static ByteBuffer sToc;
        static ByteBuffer outdata;
        ByteBuffer buf;
        static boolean ready = false;
        static int dataLen = 10240;
        static boolean serverwrite = true;
        int totalDataLen = 0;
        static boolean sc = true;
        int delay = 1;
        static boolean readdone = false;

        static int READSIDELIMIT = 200000;
        static int WRITESIDELIMIT = 370000;

        // Turn on debugging
        static boolean debug = true;

        KeyUpdateOnce() {
            buf = ByteBuffer.allocate(dataLen * 4);
        }
        /**
         * args should have two values:  server|client, cipher suite, <limit size>
         * Prepending 'p' is for internal use only.
         */
        public static void main(String args[]) throws Exception {

        for (int i = 0; i < args.length; i++) {
            System.out.print(" " + args[i]);
        }
        System.out.println();
        if (args[0].compareTo("p") != 0) {
            boolean expectedFail = (Integer.parseInt(args[0]) == 1);
            if (expectedFail) {
                System.out.println("Test expected to not find updated msg");
            }

            // Write security property file to overwrite default
            //File f = new File("keyusage."+ System.nanoTime());
            //PrintWriter p = new PrintWriter(f);
            //p.write("jdk.tls.keyLimits= AES/GCM/NoPadding keyupdate " + WRITESIDELIMIT);
            //p.close();

            System.setProperty("test.java.opts", System.getProperty("test.java.opts") +
                " -Dtest.src=" + System.getProperty("test.src") +
                " -Dtest.jdk=" + System.getProperty("test.jdk") +
                " -Djavax.net.debug=ssl,handshake -Djavatest.maxOutputSize=99999999" +
                " --add-opens java.base/sun.security.ssl=ALL-UNNAMED"
                //" -Djava.security.properties=" + f.getName());
                              );

            System.out.println("test.java.opts: " +
                System.getProperty("test.java.opts"));

            ProcessBuilder pb = ProcessTools.createTestJavaProcessBuilder(
                Utils.addTestJavaOpts("KeyUpdateOnce", "p", args[1],
                    args[2]));

            OutputAnalyzer output = ProcessTools.executeProcess(pb);
            try {
                output.shouldContain(String.format(
                    "\"cipher suite\"        : \"%s", args[2]));
                if (expectedFail) {
                    output.shouldNotContain("KeyUpdate: write key updated");
                    output.shouldNotContain("KeyUpdate: read key updated");
                } else {
                    //javax.net.ssl|DEBUG|81|Thread-0|2025-12-05 09:22:14.279 PST|KeyUpdate.java:280|Produced KeyUpdate post-handshake message
                    List<String> list = output.stderrShouldContain("Thread-0")
                        .asLines().stream().filter(s ->
                            s.contains("Produced KeyUpdate post-handshake message")).toList();
                    for (String s : list) {
                        System.err.println(s);
                    }
                    System.err.println("list size = " + list.size());
                    output.shouldContain("trigger key update");
                    output.shouldContain("KeyUpdate: write key updated");
                    output.shouldContain("KeyUpdate: read key updated");
                }
            } catch (Exception e) {
                throw e;
            } finally {
                System.out.println("-- BEGIN Stdout:");
                System.out.println(output.getStdout());
                System.out.println("-- END Stdout");
                System.out.println("-- BEGIN Stderr:");
                System.out.println(output.getStderr());
                System.out.println("-- END Stderr");
            }
            return;
        }

        if (args[0].compareTo("p") != 0) {
            throw new Exception ("Tried to run outside of a spawned process");
        }

        if (args[1].compareTo("client") == 0) {
            serverwrite = false;
        }

        cTos = ByteBuffer.allocateDirect(dataLen*4);
        sToc = ByteBuffer.allocateDirect(dataLen*4);
        outdata = ByteBuffer.allocateDirect(dataLen);

        byte[] data  = new byte[dataLen];
        Arrays.fill(data, (byte)0x0A);
        outdata.put(data);
        outdata.flip();
        cTos.clear();
        sToc.clear();

        Thread ts = new Thread(serverwrite ? new Client() :
            new Server(args[2]));
        ts.start();
        (serverwrite ? new Server(args[2]) : new Client()).run();
        ts.interrupt();
        ts.join();
    }

    private static void doTask(SSLEngineResult result,
        SSLEngine engine) throws Exception {

        if (result.getHandshakeStatus() ==
            SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                print("\trunning delegated task...");
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus =
                engine.getHandshakeStatus();
            if (hsStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                throw new Exception(
                    "handshake shouldn't need additional tasks");
            }
            print("\tnew HandshakeStatus: " + hsStatus);
        }
    }

    static void print(String s) {
        if (debug) {
            System.err.println(s);
        }
    }

    static void log(String s, SSLEngineResult r) {
        if (!debug) {
            return;
        }
        System.err.println(s + ": " +
            r.getStatus() + "/" + r.getHandshakeStatus()+ " " +
            r.bytesConsumed() + "/" + r.bytesProduced() + " ");

    }

    void write() throws Exception {
        int i = 0;
        SSLEngineResult r;
        boolean again = true;
        int countdown = 5;

        while (!ready) {
            Thread.sleep(delay);
        }
        print("Write-side. ");

        while (i++ < 150) {
            while (sc) {
                if (readdone) {
                    return;
                }
                Thread.sleep(delay);
            }

            outdata.rewind();
            print("write wrap");

            while (true) {
                r = eng.wrap(outdata, getWriteBuf());
                log("write wrap", r);
                if (debug && r.getStatus() != SSLEngineResult.Status.OK) {
                    print("outdata pos: " + outdata.position() +
                        " rem: " + outdata.remaining() +
                        " lim: " + outdata.limit() +
                        " cap: " + outdata.capacity());
                    print("writebuf pos: " + getWriteBuf().position() +
                        " rem: " + getWriteBuf().remaining() +
                        " lim: " + getWriteBuf().limit() +
                        " cap: " + getWriteBuf().capacity());
                }
                if (again && r.getStatus() == SSLEngineResult.Status.OK &&
                    r.getHandshakeStatus() ==
                        SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    //print("again");
                    //again = false;
                    continue;
                }
                break;
            }
            doTask(r, eng);
            getWriteBuf().flip();
            sc = true;
            while (sc) {
                if (readdone) {
                    return;
                }
                Thread.sleep(delay);
            }

            // XXX  Maybe check put the reflecion value of read-side keyLimitCountdown, then when it goes negative,
            // skip the unwrap operation?  Have to remove the half-open on the readside.
            long rlimit = Long.MAX_VALUE;
            if (readSideInputRecord != null) {
                rlimit = getReadLimit(readSideInputRecord);
            }
            if (rlimit <= 0) {
                countdown--;
            }
            System.err.println("Write side readLimit = " + rlimit);
            while (countdown == 5 || countdown <= 0) {
                buf.clear();
                r = eng.unwrap(getReadBuf(), buf);
                log("write unwrap", r);
                if (debug && r.getStatus() != SSLEngineResult.Status.OK) {
                    print("buf pos: " + buf.position() +
                        " rem: " + buf.remaining() +
                        " lim: " + buf.limit() +
                        " cap: " + buf.capacity());
                    print("readbuf pos: " + getReadBuf().position() +
                        " rem: " + getReadBuf().remaining() +
                        " lim: " + getReadBuf().limit() +
                        " cap:"  + getReadBuf().capacity());
                }
                break;
            }
            doTask(r, eng);
            getReadBuf().compact();
            print("compacted readbuf pos: " + getReadBuf().position() +
                " rem: " + getReadBuf().remaining() +
                " lim: " + getReadBuf().limit() +
                " cap: " + getReadBuf().capacity());
            sc = true;
        }
    }

    void read() throws Exception {
        byte b = 0x0B;
        ByteBuffer buf2 = ByteBuffer.allocateDirect(dataLen);
        SSLEngineResult r = null;
        boolean exit, again = true;
        int countdown = 5;
        boolean firstOccurance = false;

        while (eng == null) {
            Thread.sleep(delay);
        }

        try {
            System.out.println("connected");
            print("entering read loop");
            ready = true;
            while (true) {

                while (!sc) {
                    Thread.sleep(delay);
                }

                print("read wrap");

                exit = false;
                while (!exit) {
                    buf2.put(b);
                    buf2.flip();
                    r = eng.wrap(buf2, getWriteBuf());
                    log("read wrap", r);
                    if (debug) {
                        // && r.getStatus() != SSLEngineResult.Status.OK) {
                        print("buf2 pos: " + buf2.position() +
                            " rem: " + buf2.remaining() +
                            " cap: " + buf2.capacity());
                        print("writebuf pos: " + getWriteBuf().position() +
                            " rem: " + getWriteBuf().remaining() +
                            " cap: " + getWriteBuf().capacity());
                    }
                    if (again && r.getStatus() == SSLEngineResult.Status.OK &&
                        r.getHandshakeStatus() ==
                            SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                        buf2.compact();
                        again = false;
                        continue;
                    }
                    exit = true;
                }
                doTask(r, eng);
                buf2.clear();
                getWriteBuf().flip();

                sc = false;

                while (!sc) {
                    Thread.sleep(delay);
                }

                while (true) {
                    buf.clear();
                    r = eng.unwrap(getReadBuf(), buf);
                    log("read unwrap", r);
                    if (debug &&
                        r.getStatus() != SSLEngineResult.Status.OK) {
                        print("buf pos " + buf.position() +
                            " rem: " + buf.remaining() +
                            " lim: " + buf.limit() +
                            " cap: " + buf.capacity());
                        print("readbuf pos: " + getReadBuf().position() +
                            " rem: " + getReadBuf().remaining() +
                            " lim: " + getReadBuf().limit() +
                            " cap: " + getReadBuf().capacity());
                        doTask(r, eng);
                    }

                    if (again && r.getStatus() == SSLEngineResult.Status.OK &&
                        r.getHandshakeStatus() ==
                            SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        buf.clear();
                        print("again");
                        again = false;
                        continue;

                    }
                    break;
                }
                buf.clear();
                getReadBuf().compact();

                totalDataLen += r.bytesProduced();
                sc = false;
                if (r != null) {
                    System.err.println("rstatus = " + r.getHandshakeStatus());
                    if (r != null && !firstOccurance &&
                        r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        if (countdown == 0) {
                            try {
                                //forceKeyLimitViaReflection(eng, 200000);
                                readSideInputRecord = getInputRecord(eng);
                                setReadLimit(readSideInputRecord, 200000);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                            System.err.println("Resetting readside");
                            firstOccurance = true;
                            //eng.closeOutbound();
                            /*
                            while (true) {
                                Thread.sleep(delay);
                                System.err.println("read side off");
                                sc = false;
                            }

                            */
                        }
                        countdown--;
                    }
                } else {
                    System.err.println("rstatus = null");
                }
            }
        } catch (Exception e) {
            sc = false;
            readdone = true;
            System.out.println(e.getMessage());
            e.printStackTrace();
            System.out.println("Total data read = " + totalDataLen);
        }
    }

    static Object readSideInputRecord  = null;
    ByteBuffer getReadBuf() {
        return null;
    }

    ByteBuffer getWriteBuf() {
        return null;
    }


    SSLContext initContext() throws Exception {
        return createServerSSLContext();
    }

    @Override
    protected SSLContextTemplate.ContextParameters getServerContextParameters() {
        return new SSLContextTemplate.ContextParameters("TLSv1.3", "PKIX", "NewSunX509");
    }

    static Object getInputRecord(SSLEngine eng) throws Exception {
        Class<?> Cls = Class.forName("sun.security.ssl.SSLEngineImpl");
        var conContext = getPrivate(eng, Cls, "conContext");
        Class<?> transportCtxCls = Class.forName("sun.security.ssl.TransportContext");
        return getPrivate(conContext, transportCtxCls, "inputRecord");
    }

    static void setReadLimit(Object inputRecord, long newCountdown) throws Exception {
        Class<?> inputRecordCls = Class.forName("sun.security.ssl.InputRecord");
        var readCipher = getPrivate(inputRecord, inputRecordCls, "readCipher");
        var sslReadCipher = readCipher.getClass().getSuperclass();
        Field f = getField(sslReadCipher,"keyLimitCountdown");
        f.setLong(readCipher, newCountdown);
    }

    static long getReadLimit(Object inputRecord) throws Exception {
        Class<?> inputRecordCls = Class.forName("sun.security.ssl.InputRecord");
        var readCipher = getPrivate(inputRecord, inputRecordCls, "readCipher");
        var sslReadCipher = readCipher.getClass().getSuperclass();
        Field f = getField(sslReadCipher,"keyLimitCountdown");
        return f.getLong(readCipher);
    }

    static void forceKeyLimitViaReflection(SSLEngine sslSocket, long newCountdown) throws Exception {
        // Requires: --add-opens java.base/sun.security.ssl=ALL-UNNAMED
            Class<?> Cls = Class.forName("sun.security.ssl.SSLEngineImpl");
        if (!Cls.isInstance(sslSocket)) {
            throw new IllegalStateException("Not a sun.security.ssl.SSLSocketImpl at runtime.");
        }

        // SSLSocketImpl -> conContext (TransportContext)
        var conContext = getPrivate(sslSocket, Cls, "conContext");

        // TransportContext -> inputRecord, outputRecord
        Class<?> transportCtxCls = Class.forName("sun.security.ssl.TransportContext");
        var inputRecord = getPrivate(conContext, transportCtxCls, "inputRecord");
        var outputRecord = getPrivate(conContext, transportCtxCls, "outputRecord");

        Class<?> inputRecordCls = Class.forName("sun.security.ssl.InputRecord");
        System.err.println("inputRecord " + (inputRecord == null ? "null" : inputRecord));
        System.err.println("outputRecord " + (outputRecord == null ? "null" : outputRecord));
        // InputRecord/OutputRecord -> readCipher/writeCipher (names differ across updates; try both)
        //Class<?> readCipherCls = Class.forName("sun.security.ssl.SSLCipher.SSLReadCipher");
        Object readCipher = getPrivate(inputRecord, inputRecordCls, "readCipher");
        System.err.println(readCipher.getClass());
        System.err.println(readCipher.getClass().getSuperclass());
        var sslReadCipher = readCipher.getClass().getSuperclass();
        //var readCipher = getField(inputRecord.getClass(), "readCipher");
        //var readCipher = tryGetAny(inputRecord, new String[]{"readCipher", "readCipherBox", "readCipherState"});
        var writeCipher = tryGetAny(outputRecord, new String[]{"writeCipher", "writeCipherBox", "writeCipherState"});
        // SSLCipher$SSLReadCipher / SSLCipher$SSLWriteCipher -> keyLimitEnabled=true; keyLimitCountdown=<value>
        if (readCipher != null) {
//            setBoolean(readCipher, "keyLimitEnabled", true);
            Field f = getField(sslReadCipher,"keyLimitCountdown");
            f.setLong(readCipher, newCountdown);
            //setLong(readCipher, "keyLimitCountdown", newCountdown);
            System.err.println("readCipher.keyLimit set to " + newCountdown);
        } else {
            System.err.println("readCipher is null");
        }
        if (writeCipher != null) {
            setBoolean(writeCipher, "keyLimitEnabled", true);
            setLong(writeCipher, "keyLimitCountdown", newCountdown);
        } else {
            System.err.println("writeCipher is null");
        }
    }

    private static Field getField(Class<?> type, String name) throws Exception {
        Field f = type.getDeclaredField(name);
        f.setAccessible(true); // requires --add-opens for sun.security.ssl
        return f;
    }

    private static Object getPrivate(Object target, Class<?> owner, String name) throws Exception {
        return getField(owner, name).get(target);
    }

    private static void setBoolean(Object target, String name, boolean v) throws Exception {
        Field f = getField(target.getClass(), name);
        if (f.getType() != boolean.class) throw new NoSuchFieldException(name);
        f.setBoolean(target, v);
    }

    private static void setLong(Object target, String name, long v) throws Exception {
        Field f = getField(target.getClass(), name);
        if (f.getType() != long.class) throw new NoSuchFieldException(name);
        f.setLong(target, v);
    }

    private static Object tryGetAny(Object holder, String[] names) throws Exception {
        if (holder == null) return null;
        Class<?> c = holder.getClass();
        for (String n : names) {
            System.err.println("name: " + n);
            try {
                Field f = getField(c, n);
                return f.get(holder);
            } catch (NoSuchFieldException e) {
                System.err.println("exception: " + e.getMessage());
            }
        }
        return null;
    }


    static class Server extends KeyUpdateOnce implements Runnable {
        Server(String cipherSuite) throws Exception {
            super();
            eng = initContext().createSSLEngine();
            eng.setUseClientMode(false);
            eng.setNeedClientAuth(true);
            if (cipherSuite != null && cipherSuite.length() > 0) {
                eng.setEnabledCipherSuites(new String[] { cipherSuite });
            }
        }

        public void run() {
            try {
                if (serverwrite) {
                    write();
                } else {
                    read();
                }

            } catch (Exception e) {
                    System.out.println("server: " + e.getMessage());
                e.printStackTrace();
            }
            System.out.println("Server closed");
        }

        @Override
        ByteBuffer getWriteBuf() {
                return sToc;
            }
        @Override
        ByteBuffer getReadBuf() {
                return cTos;
            }
    }


    static class Client extends KeyUpdateOnce implements Runnable {
        Client() throws Exception {
            super();
            eng = initContext().createSSLEngine();
            eng.setUseClientMode(true);
        }

        public void run() {
            try {
                if (!serverwrite) {
                    write();
                } else {
                    read();
                }
            } catch (Exception e) {
                System.out.println("client: " + e.getMessage());
                e.printStackTrace();
            }
            System.out.println("Client closed");
        }
        @Override
        ByteBuffer getWriteBuf() {
                return cTos;
            }
        @Override
        ByteBuffer getReadBuf() {
                return sToc;
            }
    }

}
