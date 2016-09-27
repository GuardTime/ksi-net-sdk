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
using Guardtime.KSI.Signature;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Signature
{
    [TestFixture]
    public class KsiSignatureDoTests
    {
        [Test]
        public void TestKsiSignatureDoOk()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok);
            Assert.NotNull(signature.CalendarHashChain, "Calendar hash chain cannot be null");
        }

        [Test]
        public void TestKsiSignatureDoWithMixedAggregationChais()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Mixed_Aggregation_Chains);
            Assert.NotNull(signature, "Signature cannot be null");
        }

        [Test]
        public void TestKsiSignatureIsExtended()
        {
            IKsiSignature signature1 = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Mixed_Aggregation_Chains);
            Assert.False(signature1.IsExtended, "IsExtended should be false.");

            IKsiSignature signature2 = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Publication_Record);
            Assert.True(signature2.IsExtended, "IsExtended should be true.");
        }

        [Test]
        public void TestKsiSignatureIdentity()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_With_Mixed_Aggregation_Chains);
            Assert.AreEqual("GT :: testA :: taavi-test :: anon", signature.Identity,
                "Invalid signature identity. Path: " + Properties.Resources.KsiSignatureDo_Ok_With_Mixed_Aggregation_Chains);

            signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_Identity);
            Assert.AreEqual("GT :: GT :: rsyslog :: ot.tDyra8", signature.Identity, "Invalid signature identity. Path: " + Properties.Resources.KsiSignatureDo_Ok_Identity);
        }

        [Test]
        public void TestKsiSignatureDoOkMissingCalendarHashChain()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record);
            Assert.Null(signature.CalendarHashChain, "Calendar hash chain must be null");
        }

        [Test]
        public void TestKsiSignatureDoOkMissingPublicationRecord()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Ok_Missing_Publication_Record_And_Calendar_Authentication_Record);
            Assert.Null(signature.PublicationRecord, "Publication record must be null");
            Assert.Null(signature.CalendarAuthenticationRecord, "Calendar authentication record must be null");
        }

        [Test]
        public void TestLegacyKsiSignatureDoOk()
        {
            IKsiSignature signature = GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Legacy_Ok);
            Assert.IsTrue(signature.IsRfc3161Signature, "RFC3161 tag must exist");
        }

        [Test]
        public void TestKsiSignatureDoInvalidType()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Type);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Invalid tag type! Class: KsiSignature; Type: 0x899;"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidContainsPublicationRecordAndCalendarAuthenticationRecord()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Contain_Publication_Record_And_Calendar_Authentication_Record);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one from publication record or calendar authentication record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidExtraTag()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Extra_Tag);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Unknown tag"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidMissingAggregationHashChain()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Aggregation_Hash_Chain);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Aggregation hash chains must exist in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidMissingCalendarHashChain()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Missing_Calendar_Hash_Chain);
            },
                Throws.TypeOf<TlvException>().With.Message.StartWith(
                    "No publication record or calendar authentication record is allowed in KSI signature if there is no calendar hash chain"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleCalendarAuthenticationRecords()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Authentication_Records);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one from publication record or calendar authentication record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleCalendarHashChain()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Calendar_Hash_Chains);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one calendar hash chain is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultiplePublicationRecords()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Publication_Records);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one from publication record or calendar authentication record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidMultipleRfc3161Records()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Multiple_Rfc_3161_Records);
            }, Throws.TypeOf<TlvException>().With.Message.StartWith("Only one RFC 3161 record is allowed in KSI signature"));
        }

        [Test]
        public void TestKsiSignatureDoInvalidHashAlgorithm()
        {
            Assert.That(delegate
            {
                GetKsiSignatureDoFromFile(Properties.Resources.KsiSignatureDo_Invalid_Hash_Algorithm);
            }, Throws.TypeOf<HashingException>().With.Message.StartWith("Invalid hash algorithm. Id: 3"));
        }

        private static IKsiSignature GetKsiSignatureDoFromFile(string file)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open))
            {
                return new KsiSignatureFactory().Create(stream);
            }
        }
    }
}