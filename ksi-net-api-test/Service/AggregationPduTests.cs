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

using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Service
{
    [TestFixture]
    public class AggregationPduTests
    {
        [Test]
        public void ToStringWithRequestPayloadTest()
        {
            AggregationPdu tag = TestUtil.GetCompositeTag<AggregationPdu>(Constants.AggregationPdu.TagType,
                new ITlvTag[]
                {
                    TestUtil.GetCompositeTag<AggregationRequestPayload>(Constants.AggregationRequestPayload.TagType, new ITlvTag[]
                    {
                        new IntegerTag(Constants.AggregationRequestPayload.RequestIdTagType, false, false, 1),
                        new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                            new DataHash(HashAlgorithm.Sha2256,
                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                        new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                        new RawTag(Constants.AggregationRequestPayload.ConfigTagType, false, false, new byte[] { 0x1 }),
                    }),
                    TestUtil.GetCompositeTag<KsiPduHeader>(Constants.KsiPduHeader.TagType,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.KsiPduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.KsiPduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.KsiPduHeader.MessageIdTagType, false, false, 2)
                        }),
                    new ImprintTag(Constants.KsiPdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                });

            AggregationPdu tag2 = new AggregationPdu(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void ToStringWithReponseTest()
        {
            AggregationPdu tag = TestUtil.GetCompositeTag<AggregationPdu>(Constants.AggregationPdu.TagType,
                new ITlvTag[]
                {
                    TestUtil.GetCompositeTag<AggregationResponsePayload>(Constants.AggregationResponsePayload.TagType, new ITlvTag[]
                    {
                        new IntegerTag(Constants.AggregationResponsePayload.RequestIdTagType, false, false, 2),
                        new IntegerTag(Constants.KsiPduPayload.StatusTagType, false, false, 1),
                        new StringTag(Constants.KsiPduPayload.ErrorMessageTagType, false, false, "Test error message."),
                        new RawTag(Constants.AggregationResponsePayload.ConfigTagType, false, false, new byte[] { 0x1 }),
                        new RawTag(Constants.AggregationResponsePayload.RequestAcknowledgmentTagType, false, false, new byte[] { 0x1 }),
                    }),
                    TestUtil.GetCompositeTag<KsiPduHeader>(Constants.KsiPduHeader.TagType,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.KsiPduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.KsiPduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.KsiPduHeader.MessageIdTagType, false, false, 2)
                        }),
                    new ImprintTag(Constants.KsiPdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                });

            AggregationPdu tag2 = new AggregationPdu(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void ToStringWithErrorTest()
        {
            AggregationPdu tag = TestUtil.GetCompositeTag<AggregationPdu>(Constants.AggregationPdu.TagType,
                new ITlvTag[]
                {
                    TestUtil.GetCompositeTag<AggregationErrorPayload>(Constants.AggregationErrorPayload.TagType, new ITlvTag[]
                    {
                        new IntegerTag(Constants.KsiPduPayload.StatusTagType, false, false, 1),
                        new StringTag(Constants.KsiPduPayload.ErrorMessageTagType, false, false, "Test Error message")
                    }),
                    TestUtil.GetCompositeTag<KsiPduHeader>(Constants.KsiPduHeader.TagType,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.KsiPduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.KsiPduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.KsiPduHeader.MessageIdTagType, false, false, 2)
                        }),
                    new ImprintTag(Constants.KsiPdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                });

            AggregationPdu tag2 = new AggregationPdu(tag);

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}