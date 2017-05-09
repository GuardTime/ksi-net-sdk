/*
 * Copyright 2013-2017 Guardtime, Inc.
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
using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class ExtendedSignatureCalendarChainAggregationTimeRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            ExtendedSignatureCalendarChainAggregationTimeRule rule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Argument null exception when no context
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            ExtendedSignatureCalendarChainAggregationTimeRule rule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
        }

        [Test]
        public void TestSignatureMissingCalendarHashChain()
        {
            ExtendedSignatureCalendarChainAggregationTimeRule rule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Check signature without calendar chain which will fail
            using (
                FileStream stream =
                    new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record),
                        FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestSignatureWithInvalidContextExtendFunctions()
        {
            ExtendedSignatureCalendarChainAggregationTimeRule rule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Check invalid extended calendar chain with invalid context functions
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContextFaultyFunctions context = new TestVerificationContextFaultyFunctions()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestRfc3161SignatureCalendarHashChainAggregationTime()
        {
            ExtendedSignatureCalendarChainAggregationTimeRule rule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Check legacy signature calendar hash chain aggregation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    ExtendedCalendarHashChain =
                        new CalendarHashChain(new RawTag(Constants.CalendarHashChain.TagType, false, false,
                            Base16.Decode(
                                "0104538FB3000204538F88D3052101145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A082101D59926FE0A1BB9DA1C543BB83595327083D1B31BC924CF646126B84A1917B68908210193A28F9135B77A59A9272B52D770BCEC86A289DAB9AB04675DC686FDBAA1E265072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000821011FA0610ABC70C14A57FB8AE7F7B3ACEF06158EFD7FEA72B8D283B6250816B9B807210100000000000000000000000000000000000000000000000000000000000000000821010B55DA6AC77E5E4D4DF01B3F7B7A4A54C40649EF8B7A6FFD374A35B0AFE6B172082101772BC22F2AE1EB91CE7004E08958110748DFD2DEBD0BDD52F1D4071728CC61F8072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101449D3D06E1A50565F5C0D9523465804D268C74384B22E08D9B9AE239A23147F507210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101DE0A153233AC4AB779C2DD9FB798937EA95728E9ABF12103BDC60BE2DB0DADE6082101A4A4B2F924477698DD230F25F8D8FA9F0FE9AB2AE6964F799E536C3FC396B5C4082101F965C19A6248ACFC6ADEF395208D352C1FBE3548484C747045FAE6FA7B98A471082101C6585B401E35921807FCD7E7312E5F317DD67A615D8ACA516F3DC47CD584D1520821014BEB537B59DA957DF787F0B48B313AB1565FF005B23F23A3C6B17EAC43A4EC2F0821016B303486CE63811ECCF8FB5EE071E471C574E661FBCAE366F8F4DC6ACFC79C400821011C102667AC4FBC8D91B99EF4A7C78BEE2448FF52AA6CD1D557595F23510E98EA082101FB79B43E0AA6BEE9173839C051D3D0DAC6F8EFBD487331B5B86A214C42FAA81C082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00")))
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureCalendarHashChainAggregationTime()
        {
            ExtendedSignatureCalendarChainAggregationTimeRule rule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Check signature calendar hash chain aggregation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    ExtendedCalendarHashChain =
                        new CalendarHashChain(new RawTag(Constants.CalendarHashChain.TagType, false, false,
                            Base16.Decode(
                                "010456C0D6A9020456C0D6A90521012C8149F374FDDCD5443456BC7E8FFA310B7FE090DAA98C0980B81EC2407FD0130821011A039DE0761EEC75F6CCB4B17720E0565AC694BB8B2211BB30B22DD9AC45F931082101F7D776798EFF2A0B75FFD135D45F2717C25909BAF482A04CF15F70C4E2BD75A7082101E994F25C01928F616C1D4B5F3715CD70586FAC3DF056E40FC88B5E7F3D11FBBF082101F5B1B5665B31B1CBE0EA66222E5905A43D7CB735ACDCF9D6C2931A23C1798797082101E47589DA097DA8C79A2B79D98A4DEA1484F28DB52A513AFD92166BF4894379C3082101F4C67A2D3BD0C46CF9064C3909A41A0D3178CCE6B729E700CFA240E4CF04984108210102459F392EBEE422991B251625C9E9E63C6394A8D1307EC9036BFCEB48E3F43108210182E16E325B51C2D8B29494DDB9DE3CB2718A8F135D8F2B1D1D2AD240A60B306F0821015234BB37CEAA00A36D44AABFC25215B1899573CE1A76827F070D7D2C68AF9DE608210136E2E89E8F3928F80A6D89AD666354E145473B2C6FF683F0796DAA68F2004545082101E44F0A3EA272C03DEFC1825D3148F0DC4060CF6BAF04F3ACD0B9AFA9EE52CAD5082101A0698E6B45EDEEAF9037E49F668114617CA60124F0FC416D017D06D78CA4295A082101A6F082B82280F3A6AFB14C8E39B7F57860B857B70CA57AFD35F40395EEB32458082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00"
                                )))
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureExtendedCalendarHashChainAggregationTimeDiffers()
        {
            ExtendedSignatureCalendarChainAggregationTimeRule rule = new ExtendedSignatureCalendarChainAggregationTimeRule();

            // Check invalid signature with invalid aggregation time
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_With_Publication_Record), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    ExtendedCalendarHashChain =
                        new CalendarHashChain(new RawTag(Constants.CalendarHashChain.TagType, false, false,
                            Base16.Decode(
                                "0104538FB3000204538F88D3052101145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A082101D59926FE0A1BB9DA1C543BB83595327083D1B31BC924CF646126B84A1917B68908210193A28F9135B77A59A9272B52D770BCEC86A289DAB9AB04675DC686FDBAA1E265072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000821011FA0610ABC70C14A57FB8AE7F7B3ACEF06158EFD7FEA72B8D283B6250816B9B807210100000000000000000000000000000000000000000000000000000000000000000821010B55DA6AC77E5E4D4DF01B3F7B7A4A54C40649EF8B7A6FFD374A35B0AFE6B172082101772BC22F2AE1EB91CE7004E08958110748DFD2DEBD0BDD52F1D4071728CC61F8072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101449D3D06E1A50565F5C0D9523465804D268C74384B22E08D9B9AE239A23147F507210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101DE0A153233AC4AB779C2DD9FB798937EA95728E9ABF12103BDC60BE2DB0DADE6082101A4A4B2F924477698DD230F25F8D8FA9F0FE9AB2AE6964F799E536C3FC396B5C4082101F965C19A6248ACFC6ADEF395208D352C1FBE3548484C747045FAE6FA7B98A471082101C6585B401E35921807FCD7E7312E5F317DD67A615D8ACA516F3DC47CD584D1520821014BEB537B59DA957DF787F0B48B313AB1565FF005B23F23A3C6B17EAC43A4EC2F0821016B303486CE63811ECCF8FB5EE071E471C574E661FBCAE366F8F4DC6ACFC79C400821011C102667AC4FBC8D91B99EF4A7C78BEE2448FF52AA6CD1D557595F23510E98EA082101FB79B43E0AA6BEE9173839C051D3D0DAC6F8EFBD487331B5B86A214C42FAA81C082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00")))
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Cal03, verificationResult.VerificationError);
            }
        }
    }
}