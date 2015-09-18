using System;
using System.Collections.Generic;

namespace Guardtime.KSI.Crypto
{
    public interface ICryptoSignatureVerifier
    {
        // TODO: make third param better
        void Verify(byte[] signedBytes, byte[] signatureBytes, Dictionary<string, object> data);
    }
}