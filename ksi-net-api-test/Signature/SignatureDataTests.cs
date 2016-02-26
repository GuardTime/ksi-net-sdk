/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;
using NUnit.Framework;

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

            CollectionAssert.AreEqual(signatureData.GetCertificateId(), new byte[] { 0xc2, 0x46, 0xb1, 0x39 }, "Certificate Id should be equal");
            CollectionAssert.AreEqual(signatureData.GetSignatureValue(),
                Base16.Decode(
                    "98D9A4D14722BB2C22425AC9112FBF6A2491B7051AD0CBFD8153E669BFCC6CDF20EEC80F7FCC7236985A4F83871DD6E245470BCA323A3902035B78764DDC4C6EB42416A3A7D7E5CEF6ED6AE8FADA668413758CF7DE1E9565EDF646170286D0F43CA30491DD3407B53DEEDDCBD2620057AB6580E3D3E938AE44EABAF3282357EEBB7B2325616755A1F20B3A78DE2F636DE10F7CCD75B6C5BB80EFEBA216F9BF1A302DCB93B9D3E3E9754620E6D8EC8672C5329CBBB00A9A4617242950D68B8A55CBA77E69DECDD49DD96F69FAA6BFBB0EF48A913F5F26AFA01FB08192D62123FC644BA2978CAF147229BD5702663494983A40ED77AA5016EAABC1FE8456DC17D4"),
                "Signature value should be correct");
            Assert.AreEqual(signatureData.SignatureType, "1.2.840.113549.1.1.11", "Signature type should be correct");
        }

        [Test]
        public void TestSignatureDataOkWithNoUri()
        {
            SignatureData signatureData = GetSignatureDataFromFile(Properties.Resources.SignatureData_Ok_No_Uri);
            Assert.AreEqual(3, signatureData.Count, "Invalid amount of child TLV objects");
        }

        [Test]
        public void TestSignatureDataInvalidWithWrongType()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Wrong_Type);
            }, "Invalid signature data type: 10");
        }

        [Test]
        public void TestSignatureDataInvalidWithExtraTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Extra_Tag);
            }, "Invalid tag");
        }

        [Test]
        public void TestSignatureDataInvalidWithoutSignatureTypeTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Signature_Type_Missing);
            }, "Only one signature type must exist in signature data");
        }

        [Test]
        public void TestSignatureDataInvalidWithMultipleSignatureTypes()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Signature_Type);
            }, "Only one signature type must exist in signature data");
        }

        [Test]
        public void TestSignatureDataInvalidWithoutSignatureValueTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Signature_Value_Missing);
            }, "Only one signature value must exist in signature data");
        }

        [Test]
        public void TestSignatureDataInvalidWithMultipleSignatureValues()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Signature_Value);
            }, "Only one signature value must exist in signature data");
        }

        [Test]
        public void TestSignatureDataInvalidWithoutCertificateIdTag()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Certificate_Id_Missing);
            }, "Only one certificate id must exist in signature data");
        }

        [Test]
        public void TestSignatureDataInvalidWithMultipleCertificateIds()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Certificate_Id);
            }, "Only one certificate id must exist in signature data");
        }

        [Test]
        public void TestSignatureDataInvalidWithMultipleCertificateRepositoryUris()
        {
            Assert.Throws<TlvException>(delegate
            {
                GetSignatureDataFromFile(Properties.Resources.SignatureData_Invalid_Multiple_Certificate_Rep_Uri);
            }, "Only one certificate repository uri is allowed in signature data");
        }

        private static SignatureData GetSignatureDataFromFile(string file)
        {
            using (TlvReader reader = new TlvReader(new FileStream(file, FileMode.Open)))
            {
                SignatureData signatureData = new SignatureData(reader.ReadTag());

                return signatureData;
            }
        }
    }
}