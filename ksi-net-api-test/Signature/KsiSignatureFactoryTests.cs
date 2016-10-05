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
        public void CreateFromStreamFromNullInvalidTest()
        {
            Assert.Throws<KsiException>(delegate
            {
                new KsiSignatureFactory().Create((Stream)null);
            });
        }

        [Test]
        public void CreateFromStreamTest()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                new KsiSignatureFactory().Create(stream);
            }
        }

        [Test]
        public void CreateFromStreamAndVerifyInvalidSignatureTest()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Invalid_Aggregation_Chain_Input_Hash), FileMode.Open))
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
        public void CreateFromStreamAndVerifyWithLevel3Test()
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok_Level3), FileMode.Open))
            {
                new KsiSignatureFactory().Create(stream, null, 3);
            }
        }

        [Test]
        public void CreateFromStreamAndVerifyWithPolicyInvalidTest()
        {
            IKsiSignature signature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok_With_Publication_Record), FileMode.Open))
            {
                signature = new KsiSignatureFactory().Create(stream);
            }

            KsiSignatureFactory signatureFactory = new KsiSignatureFactory(new PublicationBasedVerificationPolicy(),
                new TestVerificationContext()
                {
                    UserPublication = new PublicationData("AAAAAA-CVZ2AQ-AANGVK-SV7GJL-36LN65-AVJYZR-6XRZSL-HIMRH3-6GU7WR-YNRY7C-X2XECY-WFQXRB")
                });

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                // Check invalid signature
                using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok_With_Publication_Record), FileMode.Open))
                {
                    signature = signatureFactory.Create(stream);
                }
            });

            Assert.AreEqual(VerificationError.Int09.Code, ex.VerificationResult.VerificationError.Code, "Unexpected result code");
        }

        [Test]
        public void CreateFromStreamAndDoNotVerifyInvalidSignatureTest()
        {
            IKsiSignature signature;

            // Check invalid signature
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Invalid_Aggregation_Chain_Index_Mismatch), FileMode.Open))
            {
                signature = new KsiSignatureFactory(new EmptyVerificationPolicy()).Create(stream);
            }
        }

        [Test]
        public void CreateFromAggregationResponsePayloadTest()
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();

            Assert.Throws<KsiException>(delegate
            {
                signatureFactory.Create((AggregationResponsePayload)null, null);
            });

            // corrseponding hash: "019F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"

            AggregationResponsePayload aggregationResponsePayload =
                new AggregationResponsePayload(new RawTag(0x202, false, false,
                    Base16.Decode(
                        "0104B17FCBD7040005094E6F206572726F72008801006802045787650203010A030206FF030203BF0302076F0301030521019F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08060101072804267E0101610A616E6F6E206874747000620A616E6F6E3A687474700063006407053795B4FECFD0880101AF02045787650203010A030206FF030203BF0302076F05210116C268AC24F3E9E985E45E01F9DD6149FCC444876CAC31623023588DED8D3151060101072201010E031D03000C72656C6561736520746573740000000000000000000000000000072601010102210100000000000000000000000000000000000000000000000000000000000000000723022101000000000000000000000000000000000000000000000000000000000000000007230221010000000000000000000000000000000000000000000000000000000000000000082302210100000000000000000000000000000000000000000000000000000000000000000723022101BD241877DFA33D43B234418B340890591BCBED2D88109B39DF94F3F5F9AD31B50723022101358824E2F8D5AFE759F117799E1795A270C682F3D18DFCC7A8C3FC3DFAC98F01082302210121E4D7A42A9081444ADAF3F161A49C6F8DD4FDD9B9BD8D75239E6215A1B26A350723022101000000000000000000000000000000000000000000000000000000000000000007230221010E0AF9E1147DA4F91FA8A47E236AC22B99C9334ECA89E1258E398A136556EFC48801018602045787650203010A030206FF030203BF052101E2838A7C174327FEDC778809244D9D81BF5A74F21C9B85D23E00A120A3A696560601010722010103031D030002475400000000000000000000000000000000000000000000000007260101070221010000000000000000000000000000000000000000000000000000000000000000072302210100000000000000000000000000000000000000000000000000000000000000000723022101761AF748890DF8B99723C0C38D0B6A0BB6949530129CC046FDD33A2700AF6D0D07230221014646FCC8CE8AC19A25EAF8E28788BE19C6B215B4EB0C8611AA0E33546CCC282E072302210100000000000000000000000000000000000000000000000000000000000000000823022101B8F57DE755C9F8BF76D0EB39C69DE3CE286E3BD54D368C5A670644AF391909D0072302210100000000000000000000000000000000000000000000000000000000000000000723022101CEAF3B94AF753270F870348EFE6460AC0866926ABAEC3676F3634BC432A3B75B880101A702045787650203010A030206FF052101042BF73DB9DC52AFCA3863A41E5D8A484B189DD18F340B09CC1453BA4C98EC510601010722010105031D030002475400000000000000000000000000000000000000000000000007260101070221010B697D7D7B562F34E7EE96526576C768F169A1508D05ADE79D871206D1AC495C0723022101FF74CA123FB933916100580A68F5E83C25C9798B2AC9F409BFE8ED76F20CF45B0723022101000000000000000000000000000000000000000000000000000000000000000007230221016763993D834A39031E492A275670D77006DCB88D88CFC17FD5263A9A83E60F8B0723022101516DB9F8EDB5B28C484EE533FBEDB46617E71AD823730CB6FB1DF8FB3819C63C072302210100000000000000000000000000000000000000000000000000000000000000000723022101E526FAC843B132E5E64EC56AFE09637A7441E3CCB4291085E326D9783742885C0823022101B7E5B1BD0D71E240FF0353FB9E075F15B390BAE7D3127CB8A5AE21BEAAAE784107230221015897E143E6185264428664B5D8EEFFB47693D37F2C446E231D2790AC82E606E8880100A402045787650203010A05210141109DFB0D25CCEF2EBDB766BFFFAA414984A4E8E33E32D052C402E06845A1C6060101082601010F02210123722145695AC78D08D683E1B91A7ECF20C8D0B76830787D43776A45156FCE21072601012C0221010C51079DEB0B51E660DB979C0039BBEC385864EB710CDBBD74DBC8B045D6263C08230221013E2035F702CEEAE861FFECB95F66692A76C267DD644A37044825C224D49814C688020219010457876502020457876502052101427C24EBEA0E2BD67950051C837C0B8AAEEA8B642B3470AF4BAE41692DEDC26D082101A4D57FE50D6F2CA58FB3A6761BE17DB575D52F0425406204EFC210DCED06DC5C082101CD53BC97E551314EA9895197F705B6A4B9014BE45F4C099A72F461973D7AF1BE0821016B0BE8486FD621AC695F234B29DB5A24FE45B76580ABAAE4DC5054B5CF468F4A0821019E4CEA0CAADAE144DA521E056E89937C690E0780C3D5EAD28894B1FB4139933B08210116EBA9C666D94258F8B6405C113A3D882C86C5B859C171ED5A88983F6D1745F00821012275407691A4A3B3E6C26C46EA8324E389AF5BAD93167A15ABF8C52802D6C68F0821011C1BE39BFC4C41B5ACF7FC3B113D41475238E5EE6D4ABC28119B05F9EC5711110821015B85EC1FA2ACA18DB7CDC936A681C6971495CB6BDD896679A223E47ADA5ECA3F0821014C23C4855510FAE15EFEBE246A01260D96C470DEBB50C63F88B2508FD6DC343708210129CB7DB7FE0C51D0F1E8B9663413AED76D7D89AC832F0D21981AE6687138CB21082101A0698E6B45EDEEAF9037E49F668114617CA60124F0FC416D017D06D78CA4295A082101A6F082B82280F3A6AFB14C8E39B7F57860B857B70CA57AFD35F40395EEB32458082101496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72082101BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE0088050151302902045787650204210133772791DDA987BDDAE37747B4A70C2A2609DF15EDBADF98B57FD4ACF0A8D0C2800B01220116312E322E3834302E3131333534392E312E312E313100800201001ED6F21A278AF0FBFA748E03DCBEC1FFE71CDD8D27D2EAD37062DF1B8FA21862AEFB0B0365080D0B0320DD13CDFB3B2EC2F2E2D71E6B989AF6477576962346D4EADAEF10931A404F420601190585E594FEF89F6B1DD4DDBCD1B3A630BF1B51304D3A6450A30E238D44378683AEECF63A7A8C141D22DC02B53CD6F9337BB0494AD7F67C370CF85B089AC04D02D403F83EB830137C1E5C0E7AD92C967D7E40EB971A79ABFAD61165C76765E6EEEDA442672A968F379CCFF83B100659A2EB516620741C69265FEF05ADB4B1030FAA8E6CE99123EC9FC349D9B1A2AA92EC279F2EF1AB1CA62DB2F9AD91AED325DA6CEEAC858EFB99E5C804968EEFDC06190B633E880304644C740D")));
            signatureFactory.Create(aggregationResponsePayload, new DataHash(Base16.Decode("019F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08")));
        }

        [Test]
        public void CreateFromPartsTest()
        {
            KsiSignatureFactory signatureFactory = new KsiSignatureFactory();
            IKsiSignature signature;

            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, Resources.KsiSignatureDo_Ok), FileMode.Open))
            {
                signature = new KsiSignatureFactory().Create(stream);
            }

            IKsiSignature newSignature = signatureFactory.Create(signature.GetAggregationHashChains(), signature.CalendarHashChain, signature.CalendarAuthenticationRecord,
                signature.PublicationRecord,
                signature.Rfc3161Record, signature.GetAggregationHashChains()[0].InputHash);

            Assert.AreEqual(signature.EncodeValue(), newSignature.EncodeValue(), "Signatures should be equal.");
        }
    }
}