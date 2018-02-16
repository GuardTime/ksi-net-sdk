﻿/*
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

using System;
using Guardtime.KSI.Crypto;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Trust
{
    [TestFixture]
    public class RsaCryptoSignatureVerifierTests
    {
        [Test]
        public void AlgorithmNullTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                KsiProvider.CreateRsaCryptoSignatureVerifier(null);
            });

            Assert.That(ex.ParamName == "algorithm", "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void SignedBytesNullTest()
        {
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                verifier.Verify(null, Base16.Decode(encodedSignature), new CryptoSignatureVerificationData(Base16.Decode(encodedCert)));
            });

            Assert.That(ex.ParamName == "signedBytes", "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void SignatureBytesNullTest()
        {
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                verifier.Verify(Base16.Decode("01"), null, new CryptoSignatureVerificationData(Base16.Decode(encodedCert)));
            });

            Assert.That(ex.ParamName == "signatureBytes", "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void CertificateNullTest()
        {
            string encodedSignedBytes = "3029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                verifier.Verify(Base16.Decode(encodedSignedBytes), Base16.Decode(encodedSignature), new CryptoSignatureVerificationData(null));
            });

            Assert.That(ex.ParamName == "certificate", "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void CryptoSignatureVerificationDataNullTest()
        {
            string encodedSignedBytes = "3029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                verifier.Verify(Base16.Decode(encodedSignedBytes), Base16.Decode(encodedSignature), null);
            });

            Assert.That(ex.ParamName == "data", "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void VerifyTest()
        {
            string encodedSignedBytes = "3029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            verifier.Verify(Base16.Decode(encodedSignedBytes),
                Base16.Decode(encodedSignature),
                new CryptoSignatureVerificationData(Base16.Decode(encodedCert)));
        }

        [Test]
        public void VerifyWithRandomSignatureBytesTest()
        {
            string encodedSignedBytes = "3029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            string encodedSignature = "0102030405";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                verifier.Verify(Base16.Decode(encodedSignedBytes),
                    Base16.Decode(encodedSignature),
                    new CryptoSignatureVerificationData(Base16.Decode(encodedCert)));
            });

            Assert.That(ex.Message.StartsWith("Failed to verify RSA signature"), "Unexpected exception message: " + ex.Message);
            Assert.IsNull(ex.InnerException);
        }

        [Test]
        public void VerifyWithRandomCertBytesTest()
        {
            string encodedSignedBytes = "3029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            string encodedCert = "0102030405";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            PkiVerificationErrorException ex = Assert.Throws<PkiVerificationErrorException>(delegate
            {
                verifier.Verify(Base16.Decode(encodedSignedBytes),
                    Base16.Decode(encodedSignature),
                    new CryptoSignatureVerificationData(Base16.Decode(encodedCert)));
            });

            Assert.That(ex.Message.StartsWith("Could not create certificate from given bytes"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void VerifyWithTimeTest()
        {
            string encodedSignedBytes = "3029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
            verifier.Verify(Base16.Decode(encodedSignedBytes),
                Base16.Decode(encodedSignature),
                new CryptoSignatureVerificationData(Base16.Decode(encodedCert), Util.ConvertDateTimeToUnixTime(new DateTime(2016, 1, 1, 0, 0, 0, DateTimeKind.Utc))));
        }

        [Test]
        public void VerifyWithTimeExpiredTest()
        {
            string encodedSignedBytes = "3029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            PkiVerificationFailedCertNotValidException ex = Assert.Throws<PkiVerificationFailedCertNotValidException>(delegate
            {
                ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
                verifier.Verify(Base16.Decode(encodedSignedBytes),
                    Base16.Decode(encodedSignature),
                    // test with time 2015.12.31
                    new CryptoSignatureVerificationData(Base16.Decode(encodedCert), Util.ConvertDateTimeToUnixTime(new DateTime(2015, 12, 31))));
            });

            Assert.That(ex.Message.StartsWith("Certificate not valid at"), "Unexpected exception message: " + ex.Message);
        }

        [Test]
        public void VerifyWithModifiedSignedBytesTest()
        {
            string encodedModifiedSignedBytes = "0029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA256");
                verifier.Verify(Base16.Decode(encodedModifiedSignedBytes),
                    Base16.Decode(encodedSignature),
                    new CryptoSignatureVerificationData(Base16.Decode(encodedCert)));
            });

            Assert.That(ex.Message.StartsWith("Failed to verify RSA signature"), "Unexpected exception message: " + ex.Message);
            Assert.IsNull(ex.InnerException);
        }

        [Test]
        public void VerifyWithWrongAlgorithmTest()
        {
            string encodedModifiedSignedBytes = "0029020456C0D6A904210187EBC5594827DC2B3F87918DC7AFE8A528E844D65918CD525984D65981C2C79A";
            // valid from 2016.01.01 - 2026.01.01
            string encodedCert =
                "308201A730820110A00302010202100096577055BF04943952E580CD2DF257300D06092A864886F70D01010B050030123110300E06035504030C0774657374696E67301E170D3136303130313030303030305A170D3236303130313030303030305A30123110300E06035504030C0774657374696E6730819F300D06092A864886F70D010101050003818D0030818902818100E66DC137E4F856EADB0D47C280BED297D70191287919FD6EBF1195DF5E821EA867F861E551A37762E3CAEBB32B1DE7E0143529F1678A87BCE2C8E5D5185F25EEC3ABC7E295EEBC64EFE4BC8ADB412A99D3F9125D30C45F887632DE4B95AA169B79D1A6FD4E735255632341ED41B5BFA828975A4F1501B02C2277CA15BD470DAB0203010001300D06092A864886F70D01010B050003818100A7668A7341CC50F71045D80419AFC648FAA869DCDAD248C7BCA171EBDF54EA4FFE7D339B5A227402A2E23B554BF0E1570FFB6D0F47F3EE155984CCD3A3676C66A780560CE0A3B75B0F6D83D25FBE0B19B7491114529F208470060BFEAB1F91CA59940D53FCFA277B6E3BAE0057AD7CD2C9549B9CCF4FBF942E37B13ACC430302";

            string encodedSignature =
                "4B08D8DE7AFB3390FD6F315877EBEB55DA4F259E57BC6A282EA00373D43FC32ECC462500CACD353DFE4916EBFD58B89D72F204668223177263DF1963934326EAABE70FDB70C9238C35C3BBAC842FE9BF205C5AD0AE5A691CC26306AAB20129FA5F9C8711E4D0ED3118FFE32B6C97572A8D6700A3471B90023A60FF71C9558E0C";

            PkiVerificationFailedException ex = Assert.Throws<PkiVerificationFailedException>(delegate
            {
                ICryptoSignatureVerifier verifier = KsiProvider.CreateRsaCryptoSignatureVerifier("SHA512");
                verifier.Verify(Base16.Decode(encodedModifiedSignedBytes),
                    Base16.Decode(encodedSignature),
                    new CryptoSignatureVerificationData(Base16.Decode(encodedCert)));
            });

            Assert.That(ex.Message.StartsWith("Failed to verify RSA signature"), "Unexpected exception message: " + ex.Message);
            Assert.IsNull(ex.InnerException);
        }
    }
}