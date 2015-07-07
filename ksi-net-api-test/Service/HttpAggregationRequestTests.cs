
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;
using NUnit.Framework;
using System;
using System.IO;

namespace Guardtime.KSI.Service
{
    [TestFixture]
    public class HttpAggregationRequestTests
    {
        [Test]
        public void TestHttpAggregationRequest()
        {
            KsiService ksiService = new KsiService(new HttpKsiServiceProtocol(), new ServiceCredentials("anon", "anon"));
            IAsyncResult createSignatureAsyncResult = ksiService.BeginCreateSignature(new DataHash(HashAlgorithm.Sha2256, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }), null, null);
            KsiSignature signature = ksiService.EndCreateSignature(createSignatureAsyncResult);
            Console.WriteLine(signature);

            using (var stream = new FileStream("resources/signature/signature-ok.tlv", FileMode.Open))
            {
                signature = KsiSignature.GetInstance(stream);
                Console.WriteLine(signature);
                IAsyncResult extendSignatureAsyncResult = ksiService.BeginExtendSignature(signature, null, null);
                signature = ksiService.EndExtendSignature(extendSignatureAsyncResult);
                Console.WriteLine(signature);
            }
            //IAsyncResult pubFileAsyncResult = ksiService.BeginGetPublicationsFile(null, null);
            //IAsyncResult extendSignatureAsyncresult = ksiService.BeginExtendSignature(signature, null, null);
            //Console.WriteLine(ksiService.EndExtendSignature(extendSignatureAsyncresult));
            //Console.WriteLine(ksiService.EndGetPublicationsFile(pubFileAsyncResult));
        }
    }
}