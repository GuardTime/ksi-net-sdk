using System.IO;
using NUnit.Framework;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Signature
{
    [TestFixture]
    public class SignatureDataTests
    {

        [Test]
        public void TestSignatureDataOk()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Ok, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
                Assert.AreEqual(4, signatureData.Count, "Invalid amount of child TLV objects");
            }
        }

        [Test]
        public void TestSignatureDataOkWithNoUri()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Ok_No_Uri, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
                Assert.AreEqual(3, signatureData.Count, "Invalid amount of child TLV objects");
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid signature data type: 10")]
        public void TestSignatureDataInvalidWithWrongType()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Wrong_Type, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestSignatureDataInvalidWithExtraTag()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Extra_Tag, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature type must exist in signature data")]
        public void TestSignatureDataInvalidWithoutSignatureTypeTag()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Signature_Type_Missing, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature type must exist in signature data")]
        public void TestSignatureDataInvalidWithMultipleSignatureTypes()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Multiple_Signature_Type, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature value must exist in signature data")]
        public void TestSignatureDataInvalidWithoutSignatureValueTag()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Signature_Value_Missing, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature value must exist in signature data")]
        public void TestSignatureDataInvalidWithMultipleSignatureValues()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Multiple_Signature_Value, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one certificate id must exist in signature data")]
        public void TestSignatureDataInvalidWithoutCertificateIdTag()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Certificate_Id_Missing, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one certificate id must exist in signature data")]
        public void TestSignatureDataInvalidWithMultipleCertificateIds()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Multiple_Certificate_Id, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one certificate repository uri is allowed in signature data")]
        public void TestSignatureDataInvalidWithMultipleCertificateRepUris()
        {
            using (var stream = new FileStream(Properties.Resources.SignatureData_Invalid_Multiple_Certificate_Rep_Uri, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();
            }
        }
    }
}
