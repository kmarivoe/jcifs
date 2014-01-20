package jcifs.dcerpc.msrpc;

import jcifs.dcerpc.UnicodeString;
import jcifs.dcerpc.msrpc.samr.IntArray;
import jcifs.dcerpc.msrpc.samr.SamrLookupNamesInDomain;


public class MsrpcSamrLookupNames extends SamrLookupNamesInDomain {
    public MsrpcSamrLookupNames(SamrDomainHandle handle, UnicodeString[] names) {
        super(handle, names.length, names, new IntArray(), new IntArray());
        ptype = 0;
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }
}
