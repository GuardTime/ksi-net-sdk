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
            SignatureData signatureData = GetSignatureDataFromFile(Properties.Resources.SignatureData_Ok);
            Assert.AreEqual(4, signatureData.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestSignatureDataOkWithNoUri()
        {
            SignatureData signatureData = GetSignatureDataFromFile(Properties.Resources.SignatureData_Ok_No_Uri);
            Assert.AreEqual(3, signatureData.Count, "Invalid amount of child TLV objects");
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid signature data type: 10")]
        public void TestSignatureDataInvalidWithWrongType()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Wrong_Type);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Invalid tag")]
        public void TestSignatureDataInvalidWithExtraTag()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Extra_Tag);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature type must exist in signature data")]
        public void TestSignatureDataInvalidWithoutSignatureTypeTag()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Signature_Type_Missing);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature type must exist in signature data")]
        public void TestSignatureDataInvalidWithMultipleSignatureTypes()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Signature_Type);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature value must exist in signature data")]
        public void TestSignatureDataInvalidWithoutSignatureValueTag()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Signature_Value_Missing);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one signature value must exist in signature data")]
        public void TestSignatureDataInvalidWithMultipleSignatureValues()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Signature_Value);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one certificate id must exist in signature data")]
        public void TestSignatureDataInvalidWithoutCertificateIdTag()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Certificate_Id_Missing);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one certificate id must exist in signature data")]
        public void TestSignatureDataInvalidWithMultipleCertificateIds()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Certificate_Id);
        }

        [Test, ExpectedException(typeof(InvalidTlvStructureException), ExpectedMessage = "Only one certificate repository uri is allowed in signature data")]
        public void TestSignatureDataInvalidWithMultipleCertificateRepUris()
        {
            GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Certificate_Rep_Uri);
        }

        private SignatureData GetSignatureDataFromFile(string file)
        {
            using (var stream = new FileStream(file, FileMode.Open))
            using (var reader = new TlvReader(stream))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());
                signatureData.IsValidStructure();

                return signatureData;
            }
        }
    }
}
