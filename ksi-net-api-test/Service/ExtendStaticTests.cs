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
using System.Security.Cryptography.X509Certificates;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Test.Crypto;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Trust;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    /// <summary>
    /// Extending tests with static response
    /// </summary>
    [TestFixture]
    public class ExtendStaticTests
    {
        /// <summary>
        /// Test extending and verifying.
        /// </summary>
        [Test]
        public void ExtendndVerifyPduStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            byte[] requestResult =
                Base16.Decode(
                    "830003AB01110105616E6F6E00020457ECB2F50302041483020371010407A97298040005094E6F206572726F7200100457F2019488020354010456C11500020456C0D6A90521012C8149F374FDDCD5443456BC7E8FFA310B7FE090DAA98C0980B81EC2407FD0130821011A039DE0761EEC75F6CCB4B17720E0565AC694BB8B2211BB30B22DD9AC45F9310721013A23B4518A0A73BB2BED9087857D9D27E2B36BDEAE2BB75600D97A7FB278B93F072101AAFF5F7AC584B2BDDCC60F5920259D1726399EA5B72F3EE52F0F343FDEFBA44A082101F7D776798EFF2A0B75FFD135D45F2717C25909BAF482A04CF15F70C4E2BD75A7072101F06569DB8E8370014BFDD867FBA440717D3207EA8629A15918EDD20772DF7ADF082101E994F25C01928F616C1D4B5F3715CD70586FAC3DF056E40FC88B5E7F3D11FBBF0721015251B1496CABF85D2FB6E7D029AE026FBAAF69018ECBD480C746174ACCF3974B082101F5B1B5665B31B1CBE0EA66222E5905A43D7CB735ACDCF9D6C2931A23C17987970721011C392604BA9550C81028BFD12C41A8CD880FACF1970B2F1FE03F616D06257C19082101E47589DA097DA8C79A2B79D98A4DEA1484F28DB52A513AFD92166BF4894379C3082101F4C67A2D3BD0C46CF9064C3909A41A0D3178CCE6B729E700CFA240E4CF04984107210137E949ABAF6636312569F29CAB705E9A45DB96A15BFB26BC26403F60D489416208210102459F392EBEE422991B251625C9E9E63C6394A8D1307EC9036BFCEB48E3F431072101255FE067AFB88E68FA9957626FD72553C3ADFC85B6072145DDFCDE94CC22FE5108210182E16E325B51C2D8B29494DDB9DE3CB2718A8F135D8F2B1D1D2AD240A60B306F0821015234BB37CEAA00A36D44AABFC25215B1899573CE1A76827F070D7D2C68AF9DE60721015786F1B0135C3A37C66C3958A32F7E90123BB9C8137A98861C6307C70079842C08210136E2E89E8F3928F80A6D89AD666354E145473B2C6FF683F0796DAA68F2004545082101E44F0A3EA272C03DEFC1825D3148F0DC4060CF6BAF04F3ACD0B9AFA9EE52CAD5082101A0698E6B45EDEEAF9037E49F668114617CA60124F0FC416D017D06D78CA4295A082101A6F082B82280F3A6AFB14C8E39B7F57860B857B70CA57AFD35F40395EEB32458082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE001F210131A74D44A4032D5D152AEA8C45561D22EA64C204DF5D66B4C6AD84889208AD8F");

            Ksi ksi = GetKsi(requestResult);

            ksi.Extend(signature);
        }

        /// <summary>
        /// Test extending and verifying. Get extending request result from given signature
        /// </summary>
        [Test]
        public void ExtendAndVerifyStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            Ksi ksi = GetKsi(signature.CalendarHashChain);

            ksi.Extend(signature, signature.CalendarHashChain.PublicationData);
        }

        /// <summary>
        /// Test exteding and verification fail
        /// </summary>
        [Test]
        public void ExtendAndVerifyInvalidStaticTest()
        {
            IKsiSignature signature = new KsiSignatureFactory().Create(
                File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok)));

            CalendarHashChain calendarHashChain = new KsiSignatureFactory() { DisableVerification = true }.
                Create(File.ReadAllBytes(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Invalid_Calendar_Chain_Input_Hash))).CalendarHashChain;

            Ksi ksi = GetKsi(calendarHashChain);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                ksi.Extend(signature, calendarHashChain.PublicationData);
            });

            Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
            Assert.IsNotNull(ex.Signature);
            Assert.AreEqual(VerificationError.Int03.Code, ex.VerificationResult.VerificationError.Code);
        }

        private static Ksi GetKsi(CalendarHashChain extendResult)
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                ExtendResult = extendResult
            };

            return new Ksi(new KsiService(protocol, new ServiceCredentials("test", "test"), protocol, new ServiceCredentials("test", "test"), protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com")))));
        }

        private static Ksi GetKsi(byte[] requestResult)
        {
            TestKsiServiceProtocol protocol = new TestKsiServiceProtocol
            {
                RequestResult = requestResult
            };

            return new Ksi(new KsiService(protocol, new ServiceCredentials("anon", "anon"), protocol, new ServiceCredentials("anon", "anon"), protocol,
                new PublicationsFileFactory(
                    new PkiTrustStoreProvider(new X509Store(StoreName.Root),
                        CryptoTestFactory.CreateCertificateSubjectRdnSelector("E=publications@guardtime.com")))));
        }
    }
}