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

using System;
using System.IO;
using System.Linq;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Publication;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Signature.Verification;
using Guardtime.KSI.Signature.Verification.Policy;
using Guardtime.KSI.Test.Properties;
using Guardtime.KSI.Utils;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class KsiSignatureTests
    {
        [Test]
        public void TestKsiSignatureOk()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            Assert.NotNull(signature.CalendarHashChain, "Calendar hash chain cannot be null");
            Assert.NotNull(signature.CalendarAuthenticationRecord, "Calendar auth record cannot be null");
        }

        [Test]
        public void TestKsiSignatureWithMixedAggregationChais()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok_With_Mixed_Aggregation_Chains);
            Assert.NotNull(signature, "Signature cannot be null");
        }

        [Test]
        public void TestKsiSignatureIsExtended()
        {
            IKsiSignature signature1 = GetKsiSignatureFromFile(Resources.KsiSignature_Ok_With_Mixed_Aggregation_Chains);
            Assert.False(signature1.IsExtended, "IsExtended should be false.");

            IKsiSignature signature2 = GetKsiSignatureFromFile(Resources.KsiSignature_Ok_With_Publication_Record);
            Assert.True(signature2.IsExtended, "IsExtended should be true.");
        }

        [Test]
        public void TestKsiSignatureExtendWithoutCalendarHashChain()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            ArgumentNullException ex = Assert.Throws<ArgumentNullException>(delegate
            {
                signature.Extend(null);
            });

            Assert.AreEqual("calendarHashChain", ex.ParamName);
        }

        [Test]
        public void TestKsiSignatureExtendWithInvalidCalendarHashChain()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok_AggregationHashChain_Only);

            KsiSignatureInvalidContentException ex = Assert.Throws<KsiSignatureInvalidContentException>(delegate
            {
                signature.Extend(GetCalendarHashChain());
            });

            Assert.That(ex.Message, Does.StartWith("Signature verification failed"));
            Assert.AreEqual(VerificationError.Int03, ex.VerificationResult.VerificationError, "Unexpected verificaton code");
        }

        [Test]
        public void TestKsiSignatureExtendWithoutPublicationRecord()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            IKsiSignature extendedSignature = signature.Extend(GetCalendarHashChain());
            Assert.True(extendedSignature.IsExtended, "IsExtended should be true.");
            Assert.AreEqual(1455494400, extendedSignature.PublicationRecord.PublicationData.PublicationTime, "Unexpected publication time");
            VerificationResult result = new DefaultVerificationPolicy().Verify(extendedSignature, null, TestUtil.GetPublicationsFile());
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
        }

        /// <summary>
        /// Extend with PublicationRecordInSignature
        /// </summary>
        [Test]
        public void TestKsiSignatureExtendWithPublicationRecordInSignature()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            PublicationRecordInSignature publicationRecord = new PublicationRecordInSignature(false, false, new ITlvTag[]
            {
                new PublicationData(1455494400, new DataHash(Base16.Decode("011878289E1A333DD85091D30F001B9F6F9ED4D428D57E049BD0EBD4DBC89BD210"))),
                new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test uri (publication record in signature)")
            });

            IKsiSignature extendedSignature = signature.Extend(GetCalendarHashChain(), publicationRecord);
            Assert.True(extendedSignature.IsExtended, "IsExtended should be true.");
            Assert.AreEqual(1455494400, extendedSignature.PublicationRecord.PublicationData.PublicationTime, "Unexpected publication time");
            VerificationResult result = new DefaultVerificationPolicy().Verify(extendedSignature, null, TestUtil.GetPublicationsFile());
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual("Test uri (publication record in signature)", extendedSignature.PublicationRecord.RepositoryUri[0], "Unexpected repository uri.");
        }

        /// <summary>
        /// Extend with PublicationRecordInPublicationFile
        /// </summary>
        [Test]
        public void TestKsiSignatureExtendWithPublicationRecordInPublicationsFile()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            byte[] publicationDataBytes =
                new PublicationData(1455494400, new DataHash(Base16.Decode("011878289E1A333DD85091D30F001B9F6F9ED4D428D57E049BD0EBD4DBC89BD210"))).Encode();
            byte[] uriTagBytes = new StringTag(Constants.PublicationRecord.PublicationRepositoryUriTagType, false, false, "Test uri (publication record in publications file)")
                .Encode();
            byte[] childBytes = new byte[publicationDataBytes.Length + uriTagBytes.Length];
            Array.Copy(publicationDataBytes, childBytes, publicationDataBytes.Length);
            Array.Copy(uriTagBytes, 0, childBytes, publicationDataBytes.Length, uriTagBytes.Length);
            PublicationRecordInPublicationFile publicationRecord =
                new PublicationRecordInPublicationFile(new RawTag(Constants.PublicationRecord.TagTypeInPublicationsFile, false, false, childBytes));

            IKsiSignature extendedSignature = signature.Extend(GetCalendarHashChain(), publicationRecord);
            Assert.True(extendedSignature.IsExtended, "IsExtended should be true.");
            Assert.AreEqual(1455494400, extendedSignature.PublicationRecord.PublicationData.PublicationTime, "Unexpected publication time");
            VerificationResult result = new DefaultVerificationPolicy().Verify(extendedSignature, null, TestUtil.GetPublicationsFile());
            Assert.AreEqual(VerificationResultCode.Ok, result.ResultCode, "Unexpected verification result code.");
            Assert.AreEqual("Test uri (publication record in publications file)", extendedSignature.PublicationRecord.RepositoryUri[0], "Unexpected repository uri.");
        }

        /// <summary>
        /// Test extend. Extended calendar hash chain right links does not match with signature calendar hash chain right links (hash mismatch).
        /// </summary>
        [Test]
        public void TestKsiSignatureExtendWithCalendarHashChainHashMismatch()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            KsiException ex = Assert.Throws<KsiException>(delegate
            {
                signature.Extend(GetCalendarHashChain(true, true));
            });

            Assert.That(ex.Message, Does.StartWith("Right links of signature calendar hash chain and extended calendar hash chain do not match"), "Unexpected error message");
        }

        /// <summary>
        /// Test extend. Extended calendar hash chain contains more right links than signature calendar hash chain.
        /// </summary>
        [Test]
        public void TestKsiSignatureExtendWithCalendarHashChainHasMoreRightLinks()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            KsiException ex = Assert.Throws<KsiException>(delegate
            {
                signature.Extend(GetCalendarHashChain(false, true));
            });

            Assert.That(ex.Message, Does.StartWith("Right links of signature calendar hash chain and extended calendar hash chain do not match"), "Unexpected error message");
        }

        /// <summary>
        /// Test extend. Extended calendar hash chain contains less right links than signature calendar hash chain.
        /// </summary>
        [Test]
        public void TestKsiSignatureExtendWithCalendarHashChainHasLessRightLinks()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok);
            KsiException ex = Assert.Throws<KsiException>(delegate
            {
                signature.Extend(GetCalendarHashChain(true));
            });

            Assert.That(ex.Message, Does.StartWith("Right links of signature calendar hash chain and extended calendar hash chain do not match"), "Unexpected error message");
        }

        [Test]
        public void TestKsiSignatureIdentity()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok_With_Mixed_Aggregation_Chains);
            IIdentity[] identity = signature.GetIdentity().ToArray();
            Assert.AreEqual(4, identity.Length, "Unexpected identity count.");
            Assert.AreEqual("GT", identity[0].ClientId, "Unexpected client id in 1st identity element");
            Assert.AreEqual("testA", identity[1].ClientId, "Unexpected client id in 2nd last identity element");
            Assert.AreEqual("taavi-test", identity[2].ClientId, "Unexpected client id in 3rd last identity element");
            Assert.AreEqual("anon", identity[3].ClientId, "Unexpected client id in last identity element");
            Assert.AreEqual("127.0.0.1", identity[3].MachineId, "Unexpected machine id last identity element");
            Assert.AreEqual(1426671056028078, identity[3].RequestTime, "Unexpected request time in last identity element");
            Assert.AreEqual(0, identity[3].SequenceNumber, "Unexpected sequence number in last identity element");
            Assert.AreEqual(IdentityType.Metadata, identity[3].IdentityType, "Unexpected identity type in last identity element");
        }

        [Test]
        public void TestKsiSignatureOkWithAggregationHashChainOnly()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Ok_AggregationHashChain_Only);
            Assert.Null(signature.CalendarHashChain, "Calendar hash chain must be null");
            Assert.Null(signature.PublicationRecord, "Publication record must be null");
            Assert.Null(signature.CalendarAuthenticationRecord, "Calendar authentication record must be null");
        }

        [Test]
        public void TestLegacyKsiSignatureOk()
        {
            IKsiSignature signature = GetKsiSignatureFromFile(Resources.KsiSignature_Legacy_Ok);
            Assert.IsTrue(signature.IsRfc3161Signature, "RFC3161 tag must exist");
        }

        [Test]
        public void TestKsiSignatureInvalidType()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Type);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Invalid tag type! Class: KsiSignature; Type: 0x899;"));
        }

        [Test]
        public void TestKsiSignatureInvalidContainsPublicationRecordAndCalendarAuthenticationRecord()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Contain_Publication_Record_And_Calendar_Authentication_Record);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one from publication record or calendar authentication record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag"));
        }

        [Test]
        public void TestKsiSignatureInvalidMissingAggregationHashChain()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Missing_Aggregation_Hash_Chain);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Aggregation hash chains must exist in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureInvalidMissingCalendarHashChain()
        {
            Assert.That(delegate
                {
                    GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Missing_Calendar_Hash_Chain);
                },
                Throws.TypeOf<TlvException>().With.Message.StartWith(
                    "No publication record or calendar authentication record is allowed in KSI signature if there is no calendar hash chain"));
        }

        [Test]
        public void TestKsiSignatureInvalidMultipleCalendarAuthenticationRecords()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Multiple_Calendar_Authentication_Records);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one from publication record or calendar authentication record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureInvalidMultipleCalendarHashChain()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Multiple_Calendar_Hash_Chains);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one calendar hash chain is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureInvalidMultiplePublicationRecords()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Multiple_Publication_Records);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one from publication record or calendar authentication record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureInvalidMultipleRfc3161Records()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Multiple_Rfc_3161_Records);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one RFC 3161 record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureInvalidHashAlgorithm()
        {
            Assert.That(delegate
            {
                GetKsiSignatureFromFile(Resources.KsiSignature_Invalid_Hash_Algorithm);
            }, Throws.TypeOf<HashingException>().With.Message.StartWith("Invalid hash algorithm. Id: 3"));
        }

        private static IKsiSignature GetKsiSignatureFromFile(string file)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open))
            {
                return new KsiSignatureFactory().Create(stream);
            }
        }

        private static CalendarHashChain GetCalendarHashChain(bool excludeLastRightLink = false, bool addExtraRightLink = false)
        {
            TlvTagBuilder builder = new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false);
            builder.AddChildTag(new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1455494400));
            builder.AddChildTag(new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 1455478441));
            builder.AddChildTag(new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                new DataHash(Base16.Decode("012C8149F374FDDCD5443456BC7E8FFA310B7FE090DAA98C0980B81EC2407FD013"))));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("011A039DE0761EEC75F6CCB4B17720E0565AC694BB8B2211BB30B22DD9AC45F931")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("013A23B4518A0A73BB2BED9087857D9D27E2B36BDEAE2BB75600D97A7FB278B93F")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("01AAFF5F7AC584B2BDDCC60F5920259D1726399EA5B72F3EE52F0F343FDEFBA44A")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01F7D776798EFF2A0B75FFD135D45F2717C25909BAF482A04CF15F70C4E2BD75A7")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("01F06569DB8E8370014BFDD867FBA440717D3207EA8629A15918EDD20772DF7ADF")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01E994F25C01928F616C1D4B5F3715CD70586FAC3DF056E40FC88B5E7F3D11FBBF")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("015251B1496CABF85D2FB6E7D029AE026FBAAF69018ECBD480C746174ACCF3974B")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01F5B1B5665B31B1CBE0EA66222E5905A43D7CB735ACDCF9D6C2931A23C1798797")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("011C392604BA9550C81028BFD12C41A8CD880FACF1970B2F1FE03F616D06257C19")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01E47589DA097DA8C79A2B79D98A4DEA1484F28DB52A513AFD92166BF4894379C3")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01F4C67A2D3BD0C46CF9064C3909A41A0D3178CCE6B729E700CFA240E4CF049841")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("0137E949ABAF6636312569F29CAB705E9A45DB96A15BFB26BC26403F60D4894162")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("0102459F392EBEE422991B251625C9E9E63C6394A8D1307EC9036BFCEB48E3F431")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("01255FE067AFB88E68FA9957626FD72553C3ADFC85B6072145DDFCDE94CC22FE51")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("0182E16E325B51C2D8B29494DDB9DE3CB2718A8F135D8F2B1D1D2AD240A60B306F")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("015234BB37CEAA00A36D44AABFC25215B1899573CE1A76827F070D7D2C68AF9DE6")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Left, false, false, Base16.Decode("015786F1B0135C3A37C66C3958A32F7E90123BB9C8137A98861C6307C70079842C")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("0136E2E89E8F3928F80A6D89AD666354E145473B2C6FF683F0796DAA68F2004545")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01E44F0A3EA272C03DEFC1825D3148F0DC4060CF6BAF04F3ACD0B9AFA9EE52CAD5")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01A0698E6B45EDEEAF9037E49F668114617CA60124F0FC416D017D06D78CA4295A")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01A6F082B82280F3A6AFB14C8E39B7F57860B857B70CA57AFD35F40395EEB32458")));
            builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01496FC0120D854E7534B992AB32EC3045B20D4BEE1BFBE4564FD092CEAFA08B72")));
            if (!excludeLastRightLink)
            {
                builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("01BB44FD36A5F3CDEE7B5C6DF3A6098A09E353335B6029F1477502588A7E37BE00")));
            }
            if (addExtraRightLink)
            {
                builder.AddChildTag(new RawTag((uint)LinkDirection.Right, false, false, Base16.Decode("012C8149F374FDDCD5443456BC7E8FFA310B7FE090DAA98C0980B81EC2407FD013")));
            }
            return new CalendarHashChain(builder.BuildTag());
        }
    }
}