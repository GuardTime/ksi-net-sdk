using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Signature.Verification;
using System;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class SignatureVerificationTests
    {

        [Test]
        public void TestVerifySignatureOk()
        {
            using (FileStream stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                KsiSignature signature = KsiSignature.GetInstance(stream);

                VerificationContext context = new VerificationContext();
                context.Signature = signature;
                context.DocumentHash = new Hashing.DataHash(new byte[] { 0x01, 0x11, 0xA7, 0x00, 0xB0, 0xC8, 0x06, 0x6C, 0x47, 0xEC, 0xBA, 0x05, 0xED, 0x37, 0xBC, 0x14, 0xDC, 0xAD, 0xB2, 0x38, 0x55, 0x2D, 0x86, 0xC6, 0x59, 0x34, 0x2D, 0x1D, 0x7E, 0x87, 0xB8, 0x77, 0x2D });
                IPolicy policy = new InternalVerificationPolicy();
                policy.Verify(context);
            }
        }

    }
}
