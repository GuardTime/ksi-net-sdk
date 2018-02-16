/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Publication;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class CalendarAuthenticationRecordSignatureVerificationRuleTests : RuleTestsBase
    {
        public override VerificationRule Rule => new CalendarAuthenticationRecordSignatureVerificationRule();

        /// <summary>
        /// Check signature with no calendar authentication record
        /// </summary>
        [Test]
        public void TestSignatureMissingCalendarAuthRecord()
        {
            TestVerificationContext context = new TestVerificationContext(TestUtil.GetSignature(Resources.KsiSignature_Ok_AggregationHashChain_Only))
            {
                PublicationsFile = new TestPublicationsFile()
            };

            TestSignatureMissingCalendarAuthRecord(context);
        }

        /// <summary>
        /// Check signature with invalid certificate id
        /// </summary>
        [Test]
        public void TestSignatureWithInvalidCertificateId()
        {
            TestVerificationContext context = new TestVerificationContext(TestUtil.GetSignature(Resources.KsiSignature_Ok))
            {
                PublicationsFile = new TestPublicationsFile()
            };

            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            }, "No certificate found in publications file with id:");
        }

        /// <summary>
        /// Check signature without publications file. 
        /// </summary>
        [Test]
        public void TestSignatureWithoutPublicationsFile()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok)
            };
            DoesThrow<KsiVerificationException>(delegate
            {
                Rule.Verify(context);
            }, "Invalid publications file in context: null");
        }

        /// <summary>
        /// Check legacy signature with publications file. 
        /// </summary>
        [Test]
        public void TestRfc3161SignatureWithPublicationsFile()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Legacy_Ok),
                PublicationsFile = TestUtil.GetPublicationsFile()
            };

            Verify(context, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Check signature and verify calendar authentication record
        /// </summary>
        [Test]
        public void TestSignatureWithPublicationFile()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(),
                PublicationsFile = TestUtil.GetPublicationsFile()
            };

            Verify(context, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Check invalid signature with invalid calendar authentication record signature
        /// </summary>
        [Test]
        public void TestSignatureWithInvalidCalendarAuthenticationRecordSignature()
        {
            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Authentication_Record_Invalid_Signature),
                PublicationsFile = TestUtil.GetPublicationsFile()
            };

            Verify(context, VerificationResultCode.Fail, VerificationError.Key02);
        }

        /// <summary>
        /// Check invalid signature with cert that was not valid at aggregation time.
        /// </summary>
        [Test]
        public void TestSignatureWithNotValidCertAtAggregationTime()
        {
            VerificationContext context = new VerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Not_Valid_Cert),
                PublicationsFile = TestUtil.GetPublicationsFile()
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Key03);
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. 
        /// </summary>
        [Test]
        public void TestPkcs7CalendarAuthenticationRecordSignature()
        {
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000E5DF21B660FDA6C8B9CDB383DF1C47300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181000EDDCA6A89605333686FDC50D86664180F15979768BD9FC22742BAEA3355D589F021226DB5D3445C9C41B5376C6180276970D5502A9101D1342A310C4C6EFA33E1747D19D42D405937E922BFFBD2B29A3A13AD884C24802857059B0F92DF840652EF608293EFA09DBD0FCF584B6E271E4B481DD4E6CA74241B63C7A7B2C57E86";
            byte[] certId = new byte[] { 1, 2, 3 };

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Calendar_Auth_Record_Pkcs7_Signature),
                PublicationsFile = GetPublicationsFile(certId, encodedCert)
            };
            Verify(context, VerificationResultCode.Ok);
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Signed bytes and signature does not match
        /// </summary>
        [Test]
        public void TestWithInvalidPkcs7CalendarAuthenticationRecordSignature()
        {
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000F8E5378C0921B3E4729551F1ED8819300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181007949A893A98EA5CF5902B75B62F8DD9219387B7E9BB10A563E85D6176C0E4DF11E9AE76E74F9445EA2B753C9B624AE1C4BBC6F68752E4576A80081C0C2EB9DFD54AEE82557E6FF67A6877FCC911CA86CE7A1051893F193B7E7CD893EEC54BDE8191696A90AC5645615C6AC9BAADF20E736F5B7BBFFBE0125A4B2C6E9020BCDCF";
            byte[] certId = new byte[] { 1, 2, 3 };

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Auth_Record_Pkcs7_Signature),
                PublicationsFile = GetPublicationsFile(certId, encodedCert)
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Key02);
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Signature bytes modified.
        /// </summary>
        [Test]
        public void TestWithInvalidPkcs7CalendarAuthenticationRecordSignatureModifiedBytes()
        {
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000F8E5378C0921B3E4729551F1ED8819300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181007949A893A98EA5CF5902B75B62F8DD9219387B7E9BB10A563E85D6176C0E4DF11E9AE76E74F9445EA2B753C9B624AE1C4BBC6F68752E4576A80081C0C2EB9DFD54AEE82557E6FF67A6877FCC911CA86CE7A1051893F193B7E7CD893EEC54BDE8191696A90AC5645615C6AC9BAADF20E736F5B7BBFFBE0125A4B2C6E9020BCDCF";
            byte[] certId = new byte[] { 1, 2, 3 };

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Auth_Record_Pkcs7_Signature_Modified_Bytes),
                PublicationsFile = GetPublicationsFile(certId, encodedCert)
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Key02);
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Signature and certificate do not match.
        /// </summary>
        [Test]
        public void TestWithInvalidPkcs7CalendarAuthenticationRecordSignatureCert()
        {
            // invalid cert

            string encodedCert =
                "308201A730820110A003020102021000A23595D54EC5CD4CE4B2C442054819300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100A75F9454CDE6E398DC17C0A34B50CFA522BCAB28BA492087C609B295BD93159A82F4ED6225A1C424FB4DE3C5D871CADA882BC7764BAFD86484C06FB582E66CF229D1B7722C847E7803C5C682C9ADBEEBE924D8402CF0464DBE34D1DAF6F319689F730ECF002298FEEB31537FBE3C5276B399DAB4441DD456200800FF6A8263310203010001300D06092A864886F70D01010B05000381810005E41DAD3113FA3F650F0D26B341022FC586C7ACC584E9B32A586EF4E1D02C84099773F8957AD5FC6971C732194047F5A0302D19A47A478B14D43FDB5838CEFEE55F55432BC86C61E76297865CBBFAA13A436585B222441D51236879FD33EBC35FFCADBE9450CEAE60AC487626732248BEF0093D45C10AF634277D8C0791E68A";
            byte[] certId = new byte[] { 1, 2, 3 };

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Calendar_Auth_Record_Pkcs7_Signature),
                PublicationsFile = GetPublicationsFile(certId, encodedCert)
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Key02);
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Certificate not valid at aggregation time.
        /// </summary>
        [Test]
        public void TestWithPkcs7NotValidCertAtAggregationTime()
        {
            // valid from 2017.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A003020102021000E919B09EB95329A7256DBE49C9BB63300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3137303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B0500038181004BBD34640D7AD7E38C50BDB72D374EBB9065241CE564A9431B18CBF45AFBFB933B151F6D4B4B1142A72B9420F0491D5CFC414B9AFAB11465AC23D48749114E12B8FE0A1F71C272C40BF2A2CCC51895A413CE79019ABDB46FBE8AC5EA2C69C4C801C70D63BFA1F27D77908238825773967552155AA79FEAFC595D7BD6F5BFFA02";
            byte[] certId = new byte[] { 1, 2, 3 };

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Invalid_Calendar_Auth_Record_Pkcs7_Signature_Not_Valid_Cert),
                PublicationsFile = GetPublicationsFile(certId, encodedCert)
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Key03);
        }

        /// <summary>
        /// Test with PKCS#7 calendar auth record signature. Invalid cert bytes.
        /// </summary>
        [Test]
        public void TestWithPkcs7InvalidCertBytes()
        {
            string encodedCert = "1234";
            byte[] certId = new byte[] { 1, 2, 3 };

            TestVerificationContext context = new TestVerificationContext()
            {
                Signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_Calendar_Auth_Record_Pkcs7_Signature),
                PublicationsFile = GetPublicationsFile(certId, encodedCert)
            };
            Verify(context, VerificationResultCode.Fail, VerificationError.Key02);
        }

        private CertificateRecord GetCertificateRecord(byte[] id, byte[] cert)
        {
            byte[] idTagBytes = new RawTag(Constants.CertificateRecord.CertificateIdTagType, false, false, id).Encode();
            byte[] certTagBytes = new RawTag(Constants.CertificateRecord.X509CertificateTagType, false, false, cert).Encode();

            MemoryStream stream = new MemoryStream();

            stream.Write(idTagBytes, 0, idTagBytes.Length);
            stream.Write(certTagBytes, 0, certTagBytes.Length);

            return new CertificateRecord(new RawTag(Constants.CertificateRecord.TagType, false, false, stream.ToArray()));
        }

        private TestPublicationsFile GetPublicationsFile(byte[] certId, string encodedCert)
        {
            TestPublicationsFile testPublicationsFile = new TestPublicationsFile();
            testPublicationsFile.CertificateRecords.Add(GetCertificateRecord(certId, Base16.Decode(encodedCert)));
            return testPublicationsFile;
        }
    }
}