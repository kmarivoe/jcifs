/* jcifs smb client library in Java
 * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.smb;

import java.io.IOException;

public class SecurityDescriptor {
    public final static long NO_OFFSET = 0l;
    public final static long DACL_OFFSET = 20l;//DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes

    // Flag values and description from: http://msdn.microsoft.com/en-us/library/cc230366(v=prot.10).aspx
    public static final long FLAG_SR = 0x8000;       // SR  Self-Relative
    public static final long FLAG_RM = 0x4000;       // RM  RM Control Valid
    public static final long FLAG_PS = 0x2000;       // PS  SACL Protected
    public static final long FLAG_PD = 0x1000;       // PD  DACL Protected
    public static final long FLAG_SI = 0x0800;       // SI  SACL Auto-Interited
    public static final long FLAG_DI = 0x0400;       // DI  DACL Auto-Inherited
    public static final long FLAG_SC = 0x0200;       // SC  SACL Computed Inheritance Required
    public static final long FLAG_DC = 0x0100;       // DC  DACL Computed Inheritance Required
    public static final long FLAG_DT = 0x0080;       // DT  DACL Trusted
    public static final long FLAG_SS = 0x0040;       // SS  Server Security
    public static final long FLAG_SD = 0x0020;       // SD  SACL Defaulted
    public static final long FLAG_SP = 0x0010;       // SP  SACL Present
    public static final long FLAG_DD = 0x0008;       // DD  DACL Defaulted
    public static final long FLAG_DP = 0x0004;       // DP  DACL Present
    public static final long FLAG_GD = 0x0002;       // GD  Group Defaulted
    public static final long FLAG_OD = 0x0001;       // OD  Owner Defaulted

    public final static long SET_DACL_CONTROL_FLAGS = FLAG_SR | FLAG_PD | FLAG_DI | FLAG_DP | FLAG_GD | FLAG_OD;

    private int type;
    private SID owner_user;
    private SID owner_group;
    private ACE[] aces;

    public SecurityDescriptor(ACE[] aces) {
        this.aces = aces;
    }

    public SecurityDescriptor() {
    }
    public SecurityDescriptor(byte[] buffer, int bufferIndex, int len) throws IOException {
        this.decode(buffer, bufferIndex);
    }
    public int decode(byte[] buffer, int bufferIndex) throws IOException {
        int start = bufferIndex;

        bufferIndex++; // revision
        bufferIndex++;
        type = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        owner_user = new SID(buffer, bufferIndex); // offset to owner sid
        bufferIndex += 4;
        owner_group = new SID(buffer, bufferIndex); // offset to group sid
        bufferIndex += 4;
        ServerMessageBlock.readInt4(buffer, bufferIndex); // offset to sacl
        bufferIndex += 4;
        int daclOffset = ServerMessageBlock.readInt4(buffer, bufferIndex);

        bufferIndex = start + daclOffset;

        bufferIndex++; // revision
        bufferIndex++;
        int size = ServerMessageBlock.readInt2(buffer, bufferIndex);
        bufferIndex += 2;
        int numAces = ServerMessageBlock.readInt4(buffer, bufferIndex);
        bufferIndex += 4;

        if (numAces > 4096)
            throw new IOException( "Invalid SecurityDescriptor" );

        if (daclOffset != 0) {
            aces = new ACE[numAces];
            for (int i = 0; i < numAces; i++) {
                aces[i] = new ACE();
                bufferIndex += aces[i].decode(buffer, bufferIndex);
            }
        } else {
            aces = null;
        }

        return bufferIndex - start;
    }

    public byte[] encodeSetDACL() {
        int acesBlockSize = 1 + 1 + 2 + 4;//revision (2) + size (2) + numOfACEs(4)
        for (ACE ace: aces) {
            acesBlockSize += ace.getACESize();
        }

        int totalSize = (int) DACL_OFFSET + acesBlockSize;
        byte[] buf = new byte[totalSize];
        int index = 0;

        // Revision
        buf[index++] = (byte) 0x01;

        // Sbz1
        buf[index++] = (byte) 0x00; // Sbz1

        // Control
        ServerMessageBlock.writeInt2(SET_DACL_CONTROL_FLAGS, buf, index);
        index += 2;

        //-------- writting offsets --------

        //offset owner
        ServerMessageBlock.writeInt4(NO_OFFSET, buf, index);
        index += 4;

        //offset group
        ServerMessageBlock.writeInt4(NO_OFFSET, buf, index);
        index += 4;

        //offset Sacl
        ServerMessageBlock.writeInt4(NO_OFFSET, buf, index);
        index += 4;

        //DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
        ServerMessageBlock.writeInt4(DACL_OFFSET, buf, index);
        index += 4;


        //----------- writing the Dcls --------

        //Revision
        buf[index++] = (byte) 0x02;
        buf[index++] = (byte) 0x00;

        ServerMessageBlock.writeInt2(acesBlockSize, buf, index);
        index += 2;

        ServerMessageBlock.writeInt4(aces.length, buf, index);
        index += 4;

        for (ACE ace : aces) {
            int size = ace.encode(buf, index);
            index += size;
        }

        return buf;
    }

    public ACE[] getAces()
    {
        return aces;
    }

    public String toString() {
        String ret = "SecurityDescriptor:\n";
        if (aces != null) {
            for (int ai = 0; ai < aces.length; ai++) {
                ret += aces[ai].toString() + "\n";
            }
        } else {
            ret += "NULL";
        }
        return ret;
    }
}
