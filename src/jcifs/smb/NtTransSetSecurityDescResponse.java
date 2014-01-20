package jcifs.smb;

/**
 * -------------- MPRV PATCH -------------
 * Implements response  for permission revocation <p>
 */
class NtTransSetSecurityDescResponse extends SmbComNtTransactionResponse
{

    NtTransSetSecurityDescResponse()
    {
        super();
    }

    int writeSetupWireFormat(byte[] dst, int dstIndex)
    {
        return 0;
    }

    int writeParametersWireFormat(byte[] dst, int dstIndex)
    {
        return 0;
    }

    int writeDataWireFormat(byte[] dst, int dstIndex)
    {
        return 0;
    }

    int readSetupWireFormat(byte[] buffer, int bufferIndex, int len)
    {
        return 0;
    }

    int readParametersWireFormat(byte[] buffer, int bufferIndex, int len)
    {
        return 0;         // no parameters
    }

    int readDataWireFormat(byte[] buffer, int bufferIndex, int len)
    {
        if (errorCode != 0)
            return 4;

        return 0;//no data
    }

    public String toString()
    {
        return new String("NtTransSetSecurityDescResponse[" +
            super.toString() + "]");
    }
}