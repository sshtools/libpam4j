/*
 *  The MIT License
 *
 *  Copyright 2011, Sun Microsystems, Inc.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

package org.jvnet.libpam.impl;

import org.jvnet.libpam.impl.CLibrary.passwd;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * FreeeBSD, OpenBSD and MacOS passwd
 *
 * struct passwd {
 *   char    *pw_name;
 *   char    *pw_passwd;
 *   uid_t   pw_uid;
 *   gid_t   pw_gid;
 *   time_t pw_change;
 *   char    *pw_class;
 *   char    *pw_gecos;
 *   char    *pw_dir;
 *   char    *pw_shell;
 *   time_t pw_expire;
 * };
 *
 * @author Sebastian Sdorra
 */
@Structure.FieldOrder({"pw_change", "pw_class", "pw_gecos",
            "pw_dir", "pw_shell", "pw_expire"})
public class BSDPasswd extends passwd {
    public BSDPasswd() {
    }

    public BSDPasswd(Pointer p) {
        super(p);
    }
    
    /* password change time */
    public long pw_change;

    /* user access class */
    public String pw_class;

    /* Honeywell login info */
    public String pw_gecos;

    /* home directory */
    public String pw_dir;

    /* default shell */
    public String pw_shell;

    /* account expiration */
    public long pw_expire;

    @Override
    public String getPwGecos() {
        return pw_gecos;
    }

    @Override
    public String getPwDir() {
        return pw_dir;
    }

    @Override
    public String getPwShell() {
        return pw_shell;
    }

}
