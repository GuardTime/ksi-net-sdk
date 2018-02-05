/*AggregationRequestPdu
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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class AggregationRequestPduTests
    {
        [Test]
        public void AggregationRequestPduWithoutPayload()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false, new ITlvTag[] { }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Payloads are missing in PDU"));
        }

        [Test]
        public void AggregationRequestPduWithMultipleHeaders()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                    new ITlvTag[]
                    {
                        new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                                new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                            }).BuildTag()),
                        new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                            new ITlvTag[]
                            {
                                new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id 1"),
                                new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                                new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                            }).BuildTag()),
                        new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                            new ITlvTag[]
                            {
                                new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id 2"),
                                new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                                new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                            }).BuildTag()),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one header must exist in PDU"));
        }

        [Test]
        public void AggregationRequestPduWithHeaderNotFirst()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                    new ITlvTag[]
                    {
                        new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                                new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                            }).BuildTag()),
                        new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                            new ITlvTag[]
                            {
                                new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                                new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                                new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                            }).BuildTag()),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Header must be the first element in PDU"));
        }

        [Test]
        public void AggregationRequestPduWithoutMac()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                    new ITlvTag[]
                    {
                        new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                            new ITlvTag[]
                            {
                                new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                                new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                                new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                            }).BuildTag()),
                        new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                                new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                            }).BuildTag()),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one MAC must exist in PDU"));
        }

        [Test]
        public void AggregationRequestPduWithMacNotLast()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                    new ITlvTag[]
                    {
                        new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                            new ITlvTag[]
                            {
                                new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                                new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                                new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                            }).BuildTag()),
                        new ImprintTag(Constants.Pdu.MacTagType, false, false,
                            new DataHash(HashAlgorithm.Sha2256,
                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                        new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                                new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                            }).BuildTag()),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("MAC must be the last element in PDU"));
        }

        [Test]
        public void ToStringWithRequestPayloadTest()
        {
            AggregationRequestPdu tag = new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                new ITlvTag[]
                {
                    new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                        }).BuildTag()),
                    new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false, new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                        new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                            new DataHash(HashAlgorithm.Sha2256,
                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                        new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                    }).BuildTag()),
                    new ImprintTag(Constants.Pdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                }).BuildTag());

            AggregationRequestPdu tag2 = new AggregationRequestPdu(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void ToStringWithRequestTest()
        {
            AggregationRequestPdu tag = new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                new ITlvTag[]
                {
                    new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                        }).BuildTag()),
                    new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false, new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                        new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                            new DataHash(HashAlgorithm.Sha2256,
                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                        new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                    }).BuildTag()),
                    new ImprintTag(Constants.Pdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                }).BuildTag());

            AggregationRequestPdu tag2 = new AggregationRequestPdu(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void InvalidAggregationPduHeaderNotFirst()
        {
            Assert.That(delegate
                {
                    new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                        new ITlvTag[]
                        {
                            new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false, new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                                new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                            }).BuildTag()),
                            new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                                new ITlvTag[]
                                {
                                    new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                                    new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                                    new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                                }).BuildTag()),
                            new ImprintTag(Constants.Pdu.MacTagType, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                        }).BuildTag());
                }, Throws.Exception.TypeOf<TlvException>().With.Message.StartWith("Header must be the first element"),
                "Creating AggregationPdu should fail when header is not the first element.");
        }

        [Test]
        public void InvalidAggregationPduMacNotLast()
        {
            Assert.That(delegate
                {
                    new AggregationRequestPdu(new TlvTagBuilder(Constants.AggregationRequestPdu.TagType, false, false,
                        new ITlvTag[]
                        {
                            new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                                new ITlvTag[]
                                {
                                    new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                                    new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                                    new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                                }).BuildTag()),
                            new ImprintTag(Constants.Pdu.MacTagType, false, false,
                                new DataHash(HashAlgorithm.Sha2256,
                                    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                            new AggregationRequestPayload(new TlvTagBuilder(Constants.AggregationRequestPayload.TagType, false, false, new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                                new ImprintTag(Constants.AggregationRequestPayload.RequestHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                new IntegerTag(Constants.AggregationRequestPayload.RequestLevelTagType, false, false, 0),
                            }).BuildTag()),
                        }).BuildTag());
                }, Throws.Exception.TypeOf<TlvException>().With.Message.StartWith("MAC must be the last element"),
                "Creating AggregationPdu should fail when mac is not the last element.");
        }
    }
}