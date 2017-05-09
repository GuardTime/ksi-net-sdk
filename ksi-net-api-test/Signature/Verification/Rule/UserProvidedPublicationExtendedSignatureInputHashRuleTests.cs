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
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Rule;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature.Verification.Rule
{
    [TestFixture]
    public class UserProvidedPublicationExtendedSignatureInputHashRuleTests
    {
        [Test]
        public void TestMissingContext()
        {
            UserProvidedPublicationExtendedSignatureInputHashRule rule = new UserProvidedPublicationExtendedSignatureInputHashRule();

            // Argument null exception when no context
            Assert.Throws<ArgumentNullException>(delegate
            {
                rule.Verify(null);
            });
        }

        [Test]
        public void TestContextMissingSignature()
        {
            UserProvidedPublicationExtendedSignatureInputHashRule rule = new UserProvidedPublicationExtendedSignatureInputHashRule();

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                TestVerificationContext context = new TestVerificationContext();

                rule.Verify(context);
            });
        }

        [Test]
        public void TestSignatureWithoutContextUserPublication()
        {
            UserProvidedPublicationExtendedSignatureInputHashRule rule = new UserProvidedPublicationExtendedSignatureInputHashRule();

            // Check signature without user publication
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
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
            UserProvidedPublicationExtendedSignatureInputHashRule rule = new UserProvidedPublicationExtendedSignatureInputHashRule();

            // Check invalid extended calendar chain from context extension function
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok), FileMode.Open))
            {
                TestVerificationContextFaultyFunctions context = new TestVerificationContextFaultyFunctions()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K")
                };

                Assert.Throws<KsiVerificationException>(delegate
                {
                    rule.Verify(context);
                });
            }
        }

        [Test]
        public void TestRfc3161SignatureUserPublicationHash()
        {
            UserProvidedPublicationExtendedSignatureInputHashRule rule = new UserProvidedPublicationExtendedSignatureInputHashRule();

            // Check legacy signature with publication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Legacy_Ok_With_Publication_Record), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    ExtendedCalendarHashChain =
                        new CalendarHashChain(new RawTag(Constants.CalendarHashChain.TagType, false, false,
                            Base16.Decode(
                                "0104538FB3000204538F88D3052101145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A082101D59926FE0A1BB9DA1C543BB83595327083D1B31BC924CF646126B84A1917B68908210193A28F9135B77A59A9272B52D770BCEC86A289DAB9AB04675DC686FDBAA1E265072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000821011FA0610ABC70C14A57FB8AE7F7B3ACEF06158EFD7FEA72B8D283B6250816B9B807210100000000000000000000000000000000000000000000000000000000000000000821010B55DA6AC77E5E4D4DF01B3F7B7A4A54C40649EF8B7A6FFD374A35B0AFE6B172082101772BC22F2AE1EB91CE7004E08958110748DFD2DEBD0BDD52F1D4071728CC61F8072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101449D3D06E1A50565F5C0D9523465804D268C74384B22E08D9B9AE239A23147F507210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101DE0A153233AC4AB779C2DD9FB798937EA95728E9ABF12103BDC60BE2DB0DADE6082101A4A4B2F924477698DD230F25F8D8FA9F0FE9AB2AE6964F799E536C3FC396B5C4082101F965C19A6248ACFC6ADEF395208D352C1FBE3548484C747045FAE6FA7B98A471082101C6585B401E35921807FCD7E7312E5F317DD67A615D8ACA516F3DC47CD584D1520821014BEB537B59DA957DF787F0B48B313AB1565FF005B23F23A3C6B17EAC43A4EC2F0821016B303486CE63811ECCF8FB5EE071E471C574E661FBCAE366F8F4DC6ACFC79C400821011C102667AC4FBC8D91B99EF4A7C78BEE2448FF52AA6CD1D557595F23510E98EA082101FB79B43E0AA6BEE9173839C051D3D0DAC6F8EFBD487331B5B86A214C42FAA81C082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00"))),
                    UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K")
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureUserPublicationHash()
        {
            UserProvidedPublicationExtendedSignatureInputHashRule rule = new UserProvidedPublicationExtendedSignatureInputHashRule();

            // Check signature with publication record
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Ok_With_Publication_Record), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream),
                    ExtendedCalendarHashChain =
                        new CalendarHashChain(new RawTag(Constants.CalendarHashChain.TagType, false, false,
                            Base16.Decode(
                                "010455CE8100020455CE34990521012E86118343FBFF0422986896C42363DB331EBDE356303C1DFC3F33B2FDC39B08082101BBB4B47BBC16730790C32134C8348BB00F6C7E8B0B6AD1D7322AC4A551C3C3C8072101720063982B36DC97ED377CDF8424418D53FC221E26B5F93144E11EC1CBCFB89B072101C31C624EF0A9BA3610676B6D6043E6AF20A63B3D52DD06E4760255DB654CD90D082101EC0C7F4EDCB5E1445B7885D72B14D0098B5A2E1C976DE03A3C2860FCF49CEC8C082101B432DC9482ECF55C342C2457322BEC05F8D14903433DB1F2D27A5CDD763072BD07210156C6B60EAA9BC83651F467D081291AE8FAADF0B02EA15CFF8BCD5A270473A949072101CDEE2EC56716FC3DA6C2E649CBB2377B8F87FC60F886E47489C8300DCC75427A082101C1C76C217C16303BC173B477E0B35BC9D9038C8E0CEC9E425D02A8CE5C103729072101A10F9C1A094AADB477D86584B56FC72AC0E6F3404A918CDAB0C00F296F7C2D4F0721018E0DA56269B5BDB836DC1F83D6BF483F9E15850FD61329C5E208D5AEB4C33D820821014018FB1C9C9EFFD337B5676B87127CD0C1444E597FD7F291C06350706C9F2D730721011F45079065B8AE60A0A2E2F8C72EA46A3BA8023AA9B222E37B8DAE4F552E1D4F0821010BD3C2B20050366102CF8A040251BDF866BFD0CDEB59EB43ECF9470E1DE68D44082101CEBE36A36A2A33A3003FD3CE955575D4466B4CB525AAD78E5E0F7D3217C5FCE9072101389C588C3C983FE9E94AB1075619634590FF7C1D2E3D8965EBAB48CCAA293DEE0721017837EBEA5261CE9A1742D3CF3B9C65973A1214B03B0CCAC6F59A59724F6E7C370821014108F102F77702E5C467B330B634196B65E57F8354B4BB69898447A73F7D05A3082101FDF7DEFF598FA3608649BCC2FDE201655245DA192F2EA96D9A59822AEB3E76CC082101556C3B03730528CFC880F22611808771F37BE30E619876BD4191575CB781A8B908210113F40DCA06B1FCFC50DBDBC8800407CBFCBD99551B7E48B2E27B532E25B1F98E082101CDF3706B596D8F396EB80F24BB58CD9AF54AB491CE2EA374C58338AEDA8CC301082101B16FF759F8A8094777E6B9759A282F5513B8B476C1AD8A6B196364D4AECEFF63082101A6F082B82280F3A6AFB14C8E39B7F57860B857B70CA57AFD35F40395EEB32458082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00"
                                ))),
                    UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K")
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }
        }

        [Test]
        public void TestSignatureInvalidAggregationRootHash()
        {
            UserProvidedPublicationExtendedSignatureInputHashRule rule = new UserProvidedPublicationExtendedSignatureInputHashRule();

            // Check invalid signature with invalid root hash
            using (FileStream stream =
                new FileStream(Path.Combine(TestSetup.LocalPath, Properties.Resources.KsiSignature_Invalid_With_Invalid_Aggregation_Root_Hash), FileMode.Open))
            {
                TestVerificationContext context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream),
                    ExtendedCalendarHashChain =
                        new CalendarHashChain(new RawTag(Constants.CalendarHashChain.TagType, false, false,
                            Base16.Decode(
                                "0104538FB3000204538F88D3052101145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A082101D59926FE0A1BB9DA1C543BB83595327083D1B31BC924CF646126B84A1917B68908210193A28F9135B77A59A9272B52D770BCEC86A289DAB9AB04675DC686FDBAA1E265072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000821011FA0610ABC70C14A57FB8AE7F7B3ACEF06158EFD7FEA72B8D283B6250816B9B807210100000000000000000000000000000000000000000000000000000000000000000821010B55DA6AC77E5E4D4DF01B3F7B7A4A54C40649EF8B7A6FFD374A35B0AFE6B172082101772BC22F2AE1EB91CE7004E08958110748DFD2DEBD0BDD52F1D4071728CC61F8072101000000000000000000000000000000000000000000000000000000000000000007210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101449D3D06E1A50565F5C0D9523465804D268C74384B22E08D9B9AE239A23147F507210100000000000000000000000000000000000000000000000000000000000000000721010000000000000000000000000000000000000000000000000000000000000000082101DE0A153233AC4AB779C2DD9FB798937EA95728E9ABF12103BDC60BE2DB0DADE6082101A4A4B2F924477698DD230F25F8D8FA9F0FE9AB2AE6964F799E536C3FC396B5C4082101F965C19A6248ACFC6ADEF395208D352C1FBE3548484C747045FAE6FA7B98A471082101C6585B401E35921807FCD7E7312E5F317DD67A615D8ACA516F3DC47CD584D1520821014BEB537B59DA957DF787F0B48B313AB1565FF005B23F23A3C6B17EAC43A4EC2F0821016B303486CE63811ECCF8FB5EE071E471C574E661FBCAE366F8F4DC6ACFC79C400821011C102667AC4FBC8D91B99EF4A7C78BEE2448FF52AA6CD1D557595F23510E98EA082101FB79B43E0AA6BEE9173839C051D3D0DAC6F8EFBD487331B5B86A214C42FAA81C082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00"))),
                    UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AAIVXJ-PLJDAG-JMMYUC-OTP2GA-ELBIDQ-OKDY3C-C3VEH2-AR35I2-OJUACP-GOGD6K")
                };

                VerificationResult verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
                Assert.AreEqual(VerificationError.Pub03, verificationResult.VerificationError);
            }
        }
    }
}