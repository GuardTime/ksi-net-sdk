using NUnit.Framework;
using Guardtime.KSI.Signature.Verification.Rule;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Signature.Verification.Rule
{
    [TestFixture()]
    public class CalendarHashChainAggregationTimeRuleTests
    {
        [Test()]
        public void TestVerify()
        {
            var rule = new CalendarHashChainAggregationTimeRule();

            // Argument null exception when no context
            Assert.Throws<KsiException>(delegate
            {
                rule.Verify(null);
            });

            // Verification exception on missing KSI signature 
            Assert.Throws<KsiVerificationException>(delegate
            {
                var context = new TestVerificationContext();

                rule.Verify(context);
            });

            // Verification exception on missing KSI signature aggregation hash chain 
            Assert.Throws<KsiVerificationException>(delegate
            {
                var context = new TestVerificationContext()
                {
                    Signature = new TestKsiSignature()
                    {
                        CalendarHashChain = new CalendarHashChain(new RawTag(CalendarHashChain.TagType, false, false, Base16.Decode("010455CE81000204538F88D3052101145C6CDA9F901A65C0B3C09896675928E1A85977280BF65C0A638C8A47BB358A082101D59926FE0A1BB9DA1C543BB83595327083D1B31BC924CF646126B84A1917B68908210193A28F9135B77A59A9272B52D770BCEC86A289DAB9AB04675DC686FDBAA1E2650721011576EBF50B7F57F291C630C4447F6C2D7C53FFB01B1A8E6D03C255B6D8192E1A072101351F142994A684EDEF7F36FC97D670CD44DAF657F0A364695E99AFE82A12185D0821011FA0610ABC70C14A57FB8AE7F7B3ACEF06158EFD7FEA72B8D283B6250816B9B80721011952CC826A54D06305221695780BA6D2A28A40E219A5E4E0286B6BF4786978F70821010B55DA6AC77E5E4D4DF01B3F7B7A4A54C40649EF8B7A6FFD374A35B0AFE6B172082101772BC22F2AE1EB91CE7004E08958110748DFD2DEBD0BDD52F1D4071728CC61F80721015F23E60BA799C079C32F70409EBADD170FFDCEE6EF9D07C0A8A42CE5AC7DE847072101C25AED220B4072B5BEC1E7CAF84D7B4E7336FE2F78B4BAB62989A20E60C3D126072101DDB4DB0658527FB6897B3C3142512B0637F0359B7FE164C0CEB7B5F16B655905082101449D3D06E1A50565F5C0D9523465804D268C74384B22E08D9B9AE239A23147F5072101E0276D72C61E4D161C90BE3AEEC3CF3E51870FFA8D373790D5561E901389551E0721013FCE89BD33B202C9F775E3CE59A272D8AD2B17F7A8C944C76F87FA040F9D16D70721015643670BDD1B6DEBBA05242FEB7423D7F29016401BE4C0F2E1AA9E824919E236082101DE0A153233AC4AB779C2DD9FB798937EA95728E9ABF12103BDC60BE2DB0DADE6082101A4A4B2F924477698DD230F25F8D8FA9F0FE9AB2AE6964F799E536C3FC396B5C4082101F965C19A6248ACFC6ADEF395208D352C1FBE3548484C747045FAE6FA7B98A471082101C6585B401E35921807FCD7E7312E5F317DD67A615D8ACA516F3DC47CD584D1520821014BEB537B59DA957DF787F0B48B313AB1565FF005B23F23A3C6B17EAC43A4EC2F0721014F91EC53886806917F95B6B901A7932A1ACB330E65068669B86908C302509DDF07210171247D359734FCF9DC706B1B1116D79266DCD4CAC6A84C32F575B34F366F3EA10721010F12570DDD1C833633CBBA07E93100DD83D7C85E1CE8BC33801D8913C0566BB60821016B303486CE63811ECCF8FB5EE071E471C574E661FBCAE366F8F4DC6ACFC79C400821011C102667AC4FBC8D91B99EF4A7C78BEE2448FF52AA6CD1D557595F23510E98EA082101FB79B43E0AA6BEE9173839C051D3D0DAC6F8EFBD487331B5B86A214C42FAA81C0721014E906ED3502247AAE4D142C8766176D7A403D413A7E0CD49F1872179FC5D6CDA082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00"))),
                    }
                };

                rule.Verify(context);
            });

            // Check signature with no calendar hash chain
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok_Missing_Calendar_Hash_Chain, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check legacy signature calendar hash chain aggregation time
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Legacy_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check signature calendar hash chain aggregation time
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Ok, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Ok, verificationResult.ResultCode);
            }

            // Check invalid signature calendar hash chain with invalid aggregation time
            using (var stream = new FileStream(Properties.Resources.KsiSignatureDo_Invalid_Calendar_Chain_Publication_Time, FileMode.Open))
            {
                var context = new TestVerificationContext()
                {
                    Signature = new KsiSignatureFactory().Create(stream)
                };

                var verificationResult = rule.Verify(context);
                Assert.AreEqual(VerificationResultCode.Fail, verificationResult.ResultCode);
            }
        }
    }
}