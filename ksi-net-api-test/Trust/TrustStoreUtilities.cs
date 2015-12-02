using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Crypto;

namespace Guardtime.KSI.Trust
{
    public static class TrustStoreUtilities
    {
        public static X509Certificate2Collection GetTrustAnchorCollection()
        {
            X509Store certStore = new X509Store(StoreName.Root);
            certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection x509Certificate2Collection = certStore.Certificates;
            certStore.Close();
            return x509Certificate2Collection;
        }
    }
}