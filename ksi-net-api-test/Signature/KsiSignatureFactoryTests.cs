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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Test.Signature.Verification;
using Guardtime.KSI.Test.Signature.Verification.Rule;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class KsiSignatureFactoryTests
    {
        [Test]
        public void CreateFromByteArrayWithNullInvalidTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new KsiSignatureFactory().Create((byte[])null);
            });
            Assert.AreEqual("bytes", ex.ParamName);
        }

        [Test]
        public void CreateFromStreamWithNullInvalidTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new KsiSignatureFactory().Create((Stream)null);
            });
            Assert.AreEqual("stream", ex.ParamName);
        }

        [Test]
        public void CreateFromPayloadWithNullInvalidTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new KsiSignatureFactory().Create((AggregationResponsePayload)null, null);
            });
            Assert.AreEqual("payload", ex.ParamName);
        }

        [Test]
        public void CreateFromLegacyPayloadWithNullInvalidTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new KsiSignatureFactory().Create((LegacyAggregationResponsePayload)null, null);
            });
            Assert.AreEqual("payload", ex.ParamName);
        }

        [Test]
        public void CreateFromPartsWithNullInvalidTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new KsiSignatureFactory().Create(null, null, null, null, null, null);
            });
            Assert.AreEqual("aggregationHashChains", ex.ParamName);
        }

        [Test]
        public void CreateByContentWithNullInvalidTest()
        {
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                new KsiSignatureFactory().CreateByContent(null);
            });
            Assert.AreEqual("value", ex.ParamName);
        }

        [Test]
        public void CreateFromStreamTest()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok), FileMode.Open))
            {
                new KsiSignatureFactory().Create(stream);
            }
        }

        [Test]
        public void CreateFromStreamAndVerifyInvalidSignatureTest()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Invalid_Aggregation_Chain_Input_Hash), FileMode.Open))
            {
                KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
                {
                    new KsiSignatureFactory().Create(stream);
                });

                Assert.That(ex.Message.StartsWith("Signature verification failed"), "Unexpected exception message: " + ex.Message);
                Assert.IsNotNull(ex.Signature);
            }
        }

        [Test]
        public void CreateFromStreamAndVerifyWithPolicyInvalidTest()
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory(new PublicationBasedVerificationPolicy(),
                new TestVerificationContext()
                {
                    UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AANGVK-SV7GJL-36LN65-AVJYZR-6XRZSL-HIMRH3-6GU7WR-YNRY7C-X2XECY-WFQXRB")
                });

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                // Check invalid signature
                using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok_With_Publication_Record), FileMode.Open))
                {
                    signatureFactory.Create(stream);
                }
            });

            Assert.AreEqual(VerificationError.Pub04.Code, ex.VerificationResult.VerificationError.Code, "Unexpected result code");
        }

        [Test]
        public void CreateFromStreamAndDoNotVerifyInvalidSignatureTest()
        {
            // Do not verify invalid signature
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Invalid_Aggregation_Chain_Index_Mismatch), FileMode.Open))
            {
                new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream);
            }
        }

        [Test]
        public void CreateFromAggregationResponsePayloadTest()
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();

            AggregationResponsePayload aggregationResponsePayload =
                new AggregationResponsePayload(new RawTag(0x2, false, false,
                    Base16.Decode(
                        "0108AFE5A27DEF7743A1040005094E6F206572726F72008801006702045A6EF58C03010B03012503010D03010B03010305210196BFBF3488DC0485775A5A2B0F9870100009630F4783AAAC73C0D72E2C3343B4060101072A04287E01016105616E6F6E0062116B736967772D74657374757365723A3100630064070563E79A43A003880100AB02045A6EF58C03010B03012503010D03010B0521013C7A08C4C6F62C5E42FEA933EC5B7EB59FA522A1664BA4560E8DAF0FBD1A810E060101072404227E0201016103475400620B414C65322D312D323A360063010A64070563E79A44C9A0072601010102210155ECF6F1FDD26FE579D3D81A6ADF93987C6DFA02D3504F313B81DD2FB95F51C40823022101C3D0F6018F79DCA5D2FEC42EF89ECC805FD288BFDD56AEDDDBE0AFB77A488D6F880100A302045A6EF58C03010B03012503010D0521011B30143F49B30B251614B2BDB98C4606E6B92F17BD967B27C2F75161C54FE100060101072204207E02010161034754006209415365322D303A310063010164070563E79A4AC5400823022101FC9E9054C97CBCE13F65CB0B733A2A227B5CE5D23C0980C3B284B27BE5ABE63407230221010F87C8F8E53E3DA5840B545AC90219617A4FEAB9F76E7DFF336D7A14814F4C70880100E802045A6EF58C03010B0301250521016F946BC6CA37CBAB00A5DE378FD7C191ADC257C7E2E67EA2F933555F9C15292E0601010720041E7E02010161034754006207414E65323A300063011364070563E79A4AFAE508230221014C7D57F20776DC3CE07742B66B6527E5286D7CA9B03762C71DC935BB6888D62D0723022101E69A7B97BF8DA43685BA8AE8375BE287FDDB548F0F6820C26B35669365C2B4C608230221019F16DB50A02F8D92AA4599841F6316707B1A662A39518A489588504B554D1B7608230221010E288C96225D2179DEF90F28BE4FE62BF2C3AD28EFB8A8F600DCCF8F6A9676F7880100A402045A6EF58C03010B0521017F0D9AE236EBE7B56FEACA0B6AC53033A6993E437E495F6CE50DA46C1096E4E10601010726010144022101D474205F20C49D3BA8D144293E6D4FD2087260D25539328035E97BF792E8F6BD072601012C0221016D6210425AAB8257DE2F6E2FDC36DBDB9E7E7C976906579EAE68C8F440C891540823022101488F69C2C30F862FDCBC1BE79BB87C81D1E47BA621BE9B88076E1AA8D2D734BB880202A501045A6EF58C02045A6EF58C0521017657A2D6FD236E05B6FB45F189B5845FED615138D3782E5D4D1DA375D66E200708210142B20235775AAEF836F21B5A12D16535A401076FC0DD40DB1C5D6C62F3349B24082101B11A0A6D1B5415EE802A8C1F0E8ADC413D52283EBD91F801F1D16DAD3AE2642D082101ADEE14D2FA3F684727AE6802CD421C76BC965AEBFA2E2010691853E968643211082101E4C451E413358603EFE08066EEDA908FB6ECB609CE0DAE3A3F835B894AA3371F082101BEE31E35A4C47ED8A44BC46DEBAD7A14A259B8CA515E80A7493FB57AD862808F0821017724A0A2A8EB1F36C89F53C4BA5884AAFD10A8DD68673E6BCFF8C7A6B969D461082101D9D4620A29065A193015C1E15A15F392E133F0A2FA19464F3C06F1E8E320D074082101582522AEB80C092A3019ADA6B1AE0ED63D0BFB46CBFC75BB5ABC9E6E17F93F6308210141C699CC60229704B2B748ADCCBCD6760483607D3CEC93F3D84FA1E5B9ED3F600821018E886DD92F0A028B9680F971E189E47C474808B5CA020B8237ADCAF84A107335082101ED4F4C983F9425003ED5F3139ACECFA58BBC3356E6ED42D0EF32EFBBB0BBE27E082101468742111669F6E9C3FF6D6EF588D4CA2E83CB019BF8294058D18D6803386FF808210146DD0425199FC10F742F8FF8FC1A6EA2F9607AEC95EF0C9345EBB619E9EA634E082101CEC119E2F9EEDA49B7CABA0BD16F39FC68B9763260C4EAFBBFCE8757A8C129C108210148DEA5B1AFDBDA4B016A138B7F52F763E6826FCB935CEA9D8B8FF1AAA6B5A53B082101EBC3AB1D86641581130AC3C7077B71B67BBA4C915530E9FE49B98769FC8DCAEB082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE0088050151302902045A6EF58C0421012EEE26A5F6FF57C8F24A0CF0546C107E6285FA0FE5962B0691EC5FDF5AF15D0C800B01220116312E322E3834302E3131333534392E312E312E3131008002010034BA0861EC8545A9ADC70F08FA82D8D16D678554320025EC2255C92996D6F19FF41F3F1FFC0D5B14152A6AD6EED9C017E460E9A9E97CE73BAB5B43672388DDDEDE524A134DB9A54770373993F706ECBBFBF249CEFB16A37F7593D4B54B4ECD84499F23D81CA6D8BF21E414F96EB7FE8CFD7863506937266EF8948E5B823E63F2025F0CFBA62D6144E37C756B23BF5DE5559BA0F358EC5E311232CC02E5D73832AEB7BBFFCE41390B4FA051051DFFB5F96710D348A97138ED97A5ACFD23CF78ED560EC509880B57CEA57580824BF849B163665C958DEB8FD3F715A7346BC89FDE9F250F67D107654945D42E62EFF452793ACFC4DC8AF9F77BC8C3A31968570B4E03048DEA135F")));
            IKsiSignature signature = signatureFactory.Create(aggregationResponsePayload,
                new DataHash(Base16.Decode("0196BFBF3488DC0485775A5A2B0F9870100009630F4783AAAC73C0D72E2C3343B4")), 1);
            Assert.AreEqual(5, signature.GetAggregationHashChains().Count, "Unexpected aggregation hash chain count.");
            Assert.AreEqual(1, signature.GetAggregationHashChains()[0].GetChainLinks()[0].LevelCorrection, "Unexpected first aggregation hash chain first link level correction.");
            Assert.IsNotNull(signature.CalendarHashChain, "Unexpected calendar hash chain: null");
            Assert.IsNotNull(signature.CalendarAuthenticationRecord, "Unexpected calendar auth record: null");
        }

        [Test]
        public void CreateFromPartsTest()
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();
            IKsiSignature signature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok), FileMode.Open))
            {
                signature = new KsiSignatureFactory().Create(stream);
            }

            IKsiSignature newSignature = signatureFactory.Create(signature.GetAggregationHashChains(), signature.CalendarHashChain, signature.CalendarAuthenticationRecord,
                signature.PublicationRecord,
                signature.Rfc3161Record, signature.InputHash);

            Assert.AreEqual(signature.EncodeValue(), newSignature.EncodeValue(), "Signatures should be equal.");
        }

        [Test]
        public void CreateRfc3161SignatureFromPartsTest()
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();
            IKsiSignature signature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Legacy_Ok_With_Publication_Record), FileMode.Open))
            {
                signature = new KsiSignatureFactory().Create(stream);
            }

            // create RFC3161 signature with publication record.
            IKsiSignature newSignature = signatureFactory.Create(signature.GetAggregationHashChains(), signature.CalendarHashChain, signature.CalendarAuthenticationRecord,
                signature.PublicationRecord,
                signature.Rfc3161Record, signature.InputHash);

            Assert.AreEqual(signature.EncodeValue(), newSignature.EncodeValue(), "Signatures should be equal.");
        }

        [Test]
        public void CreateFromPartsWithoutCalendarHashChainFailTest()
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();
            IKsiSignature signature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignature_Ok), FileMode.Open))
            {
                signature = new KsiSignatureFactory().Create(stream);
            }

            // create signature without calendar hash chain but with calendar auth record.
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                signatureFactory.Create(signature.GetAggregationHashChains(), null, signature.CalendarAuthenticationRecord, signature.PublicationRecord,
                    signature.Rfc3161Record, signature.InputHash);
            });

            Assert.That(ex.Message, Does.StartWith("No publication record or calendar authentication record is allowed in KSI signature if there is no calendar hash chain"));
        }

        [Test]
        public void CreateSignatureWithAggregationChainTest()
        {
            // Base signature input hash: {SHA-256:[5A848EE304CBE6B858ABCCFA0E8397920C226FD18B9E5A34D0048F749B2DA0EC]}

            /*                                     5A848EE
                                 / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                              5950DCA                                   D4F6E36
                        / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \                        / ‾‾‾‾‾‾‾‾‾‾‾‾‾‾ \
                     C9AF37D              \                      /                  \
                     /    \                \                    /                    \
                580192B  8D982C6        14F9189             680192B                9D982C6
            */

            IKsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_LevelCorrection3);

            CreateSignatureWithAggregationChainAndVerify(
                signature,
                new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                new AggregationHashChain.Link[]
                {
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01D4F6E36871BA12449CA773F2A36F9C0112FC74EBE164C8278D213042C772E3AB"))),
                });

            CreateSignatureWithAggregationChainAndVerify(
                signature,
                new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")),
                new AggregationHashChain.Link[]
                {
                    new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01D4F6E36871BA12449CA773F2A36F9C0112FC74EBE164C8278D213042C772E3AB"))),
                });

            CreateSignatureWithAggregationChainAndVerify(
                signature,
                new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB")),
                new AggregationHashChain.Link[]
                {
                    new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01C9AF37DD9714B338C07A7C46ACBE2786876429F556D1A2F4CE383B6DAA018B83")), null, 1),
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01D4F6E36871BA12449CA773F2A36F9C0112FC74EBE164C8278D213042C772E3AB"))),
                });

            CreateSignatureWithAggregationChainAndVerify(
                signature,
                new DataHash(Base16.Decode("01680192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")),
                new AggregationHashChain.Link[]
                {
                    new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("019D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")), null, 1),
                    new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("015950DCA0E23E65EF56D68AF94718951567EBC2EF1F54357732530FC25D925340"))),
                });

            CreateSignatureWithAggregationChainAndVerify(
                signature,
                new DataHash(Base16.Decode("019D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")),
                new AggregationHashChain.Link[]
                {
                    new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01680192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")), null, 1),
                    new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("015950DCA0E23E65EF56D68AF94718951567EBC2EF1F54357732530FC25D925340"))),
                });
        }

        [Test]
        public void CreateSignatureWithAggregationChainFailWrongLevelCorrectionTest()
        {
            IKsiSignature signature = TestUtil.GetSignature(Resources.KsiSignature_Ok_LevelCorrection3);

            // new chain does not fit, base signature first level correction is not big enough
            KsiException ex1 = Assert.Throws<KsiException>(delegate
            {
                CreateSignatureWithAggregationChainAndVerify(
                    signature,
                    new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                    new AggregationHashChain.Link[]
                    {
                        new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34")), null,
                            1),
                        new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))),
                        new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01D4F6E36871BA12449CA773F2A36F9C0112FC74EBE164C8278D213042C772E3AB"))),
                    });
            });

            Assert.That(ex1.Message.StartsWith(
                    "The aggregation hash chain cannot be added as lowest level chain. It's output level (4) is bigger than level correction of the first link of the first aggregation hash chain of the base signature (3)"),
                "Unexpected exception message: " + ex1.Message);

            // new chain does not fit, base signature first level correction is not big enough
            KsiException ex2 = Assert.Throws<KsiException>(delegate
            {
                CreateSignatureWithAggregationChainAndVerify(
                    signature,
                    new DataHash(Base16.Decode("019D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32")),
                    new AggregationHashChain.Link[]
                    {
                        new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("01680192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F1")), null,
                            2),
                        new AggregationHashChain.Link(LinkDirection.Right, new DataHash(Base16.Decode("015950DCA0E23E65EF56D68AF94718951567EBC2EF1F54357732530FC25D925340"))),
                    });
            });

            Assert.That(ex2.Message.StartsWith(
                    "The aggregation hash chain cannot be added as lowest level chain. It's output level (4) is bigger than level correction of the first link of the first aggregation hash chain of the base signature (3)"),
                "Unexpected exception message: " + ex1.Message);
        }

        [Test]
        public void CreateSignatureWithAggregationChainFailHashMismatchTest()
        {
            // cannot add new aggregation hash chain, it's output hash and base signature input hash mismatch
            KsiException ex = Assert.Throws<KsiException>(delegate
            {
                CreateSignatureWithAggregationChainAndVerify(
                    TestUtil.GetSignature(Resources.KsiSignature_Ok_LevelCorrection3),
                    new DataHash(Base16.Decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")),
                    new AggregationHashChain.Link[]
                    {
                        new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("0114F9189A45A30D856029F9537FD20C9C7342B82A2D949072AB195D95D7B32ECB"))),
                        new AggregationHashChain.Link(LinkDirection.Left, new DataHash(Base16.Decode("01D4F6E36871BA12449CA773F2A36F9C0112FC74EBE164C8278D213042C772E3AB"))),
                    });
            });

            Assert.That(ex.Message.StartsWith("The aggregation hash chain cannot be added as lowest level chain. It's output hash does not match base signature input hash"),
                "Unexpected exception message: " + ex.Message);
        }

        private static void CreateSignatureWithAggregationChainAndVerify(IKsiSignature signature, DataHash inputHash, AggregationHashChain.Link[] links,
                                                                         string expectedVerificationErrorCode = null)
        {
            IKsiSignature newSignature = new KsiSignatureFactory(
                new EmptyVerificationPolicy()).CreateSignatureWithAggregationChain(signature, inputHash, HashAlgorithm.Sha2256, links);
            VerificationResult result = new InternalVerificationPolicy().Verify(new VerificationContext(newSignature) { DocumentHash = inputHash });

            if (string.IsNullOrEmpty(expectedVerificationErrorCode))
            {
                Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result");
            }
            else
            {
                Assert.AreEqual(VerificationResultCode.Fail, result.ResultCode, "Unexpected verification result");
                Assert.AreEqual(expectedVerificationErrorCode, result.VerificationError.Code, "Unexpected verification error code");
            }
        }
    }
}