/*
 * The MIT License
 *
 * Copyright (c) 2009, Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jvnet.libpam.impl;

import org.jvnet.libpam.PAMException;

import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 * @author Kohsuke Kawaguchi
 */
public interface CLibrary extends Library {
    /**
     * Comparing http://linux.die.net/man/3/getpwnam
     * and my Mac OS X reveals that the structure of this field isn't very portable.
     * In particular, we cannot read the real name reliably.
     */
	@FieldOrder({"pw_name", "pw_passwd", "pw_uid", "pw_gid"})
    public class passwd extends Structure {

        public passwd() {
        }

        public passwd(Pointer p) {
            super(p);
        }
        
        /**
         * User name.
         */
        public String pw_name;
        /**
         * Encrypted password.
         */
        public String pw_passwd;
        public int pw_uid;
        public int pw_gid;

        // ... there are a lot more fields

        public static passwd loadPasswd(String userName) throws PAMException {
            // Use one Memory region to save the structure and the strings
            // the structure is assumed to fit into 256 bytes
            Memory mem = new Memory(256 + 4096);
            Pointer structBase = mem.share(0);
            Pointer bufferBase = mem.share(256);
            PointerByReference pbr = new PointerByReference();
            int result = libc.getpwnam_r(userName, structBase, bufferBase, 4096, pbr);
            Pointer resultPointer = pbr.getValue();
            if (resultPointer == null) {
                if(result == 0) {
                	mem.close();
                    throw new PAMException("No user information is available");
                } else {
                	mem.close();
                    throw new PAMException("Failed to retrieve user information (Error: " + result + ")");
                }
            }
            passwd res;
            if(libc instanceof BSDCLibrary) {
                res = new BSDPasswd(mem);
            } else if(libc instanceof FreeBSDCLibrary) {
                res = new FreeBSDPasswd(mem);
            } else if(libc instanceof LinuxCLibrary) {
                res = new LinuxPasswd(mem);
            } else if(libc instanceof SolarisCLibrary) {
                res = new SolarisPasswd(mem);
            } else {
                res = new passwd(mem);
            }
            res.read();
            return res;
        }

        public String getPwName() {
            return pw_name;
        }

        public String getPwPasswd() {
            return pw_passwd;
        }

        public int getPwUid() {
            return pw_uid;
        }

        public int getPwGid() {
            return pw_gid;
        }

        public String getPwGecos() {
            return null;
        }

        public String getPwDir() {
            return null;
        }

        public String getPwShell() {
            return null;
        }

    }

    @Structure.FieldOrder("gr_name")
    public class group extends Structure {
        public String gr_name;
        // ... the rest of the field is not interesting for us

    }

    Pointer calloc(int count, int size);
    Pointer strdup(String s);
    passwd getpwnam(String username);
    int getpwnam_r(String username, Pointer pwdStruct, Pointer buf, int bufSize, PointerByReference result);

    /**
     * Lists up group IDs of the given user. On Linux and most BSDs, but not on Solaris.
     * See http://www.gnu.org/software/hello/manual/gnulib/getgrouplist.html
     */
    int getgrouplist(String user, int/*gid_t*/ group, Memory groups, IntByReference ngroups);

    /**
     * getgrouplist equivalent on Solaris.
     * See http://mail.opensolaris.org/pipermail/sparks-discuss/2008-September/000528.html
     */
    int _getgroupsbymember(String user, Memory groups, int maxgids, int numgids);
    group getgrgid(int/*gid_t*/ gid);
    group getgrnam(String name);

    // other user/group related functions that are likely useful
    // see http://www.gnu.org/software/libc/manual/html_node/Users-and-Groups.html#Users-and-Groups


    public static final CLibrary libc = Instance.init();

    static class Instance {
        private static CLibrary init() {
            if (Platform.isMac() || Platform.isOpenBSD()) {
                return Native.load("c", BSDCLibrary.class);
            } else if (Platform.isFreeBSD()) {
                return Native.load("c", FreeBSDCLibrary.class);
            } else if (Platform.isSolaris()) {
                return Native.load("c", SolarisCLibrary.class);
            } else if (Platform.isLinux()) {
                return Native.load("c", LinuxCLibrary.class);
            } else {
                return Native.load("c", CLibrary.class);
            }
        }
    }
}
