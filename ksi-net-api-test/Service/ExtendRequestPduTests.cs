﻿/*
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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class ExtendRequestPduTests
    {
        [Test]
        public void ExtendRequestPduWithoutPayload()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendRequestPdu(new TlvTagBuilder(Constants.ExtendRequestPdu.TagType, false, false, new ITlvTag[] { }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Payloads are missing in PDU"));
        }

        [Test]
        public void ExtendRequestPduToStringWithRequestPayloadTest()
        {
            ExtendRequestPdu tag = new ExtendRequestPdu(new TlvTagBuilder(Constants.ExtendRequestPdu.TagType, false, false,
                new ITlvTag[]
                {
                    new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                        }).BuildTag()),
                    new ExtendRequestPayload(new TlvTagBuilder(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                        new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, 2),
                        new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, 3),
                    }).BuildTag()),
                    new ImprintTag(Constants.Pdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                }).BuildTag());

            ExtendRequestPdu tag2 = new ExtendRequestPdu(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void ExtendRequestPduToStringWithResponseTest()
        {
            ExtendResponsePdu tag = new ExtendResponsePdu(new TlvTagBuilder(Constants.ExtendResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                        }).BuildTag()),
                    new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false, new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                        new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                        new StringTag(Constants.PduPayload.ErrorMessageTagType, false, false, "Test error message."),
                        new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 1),
                        new CalendarHashChain(new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false,
                            new ITlvTag[]
                            {
                                new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1),
                                new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 0),
                                new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                                // add links
                                new ImprintTag((uint)LinkDirection.Left, false, false,
                                    new DataHash(HashAlgorithm.Sha2256,
                                        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }))
                            }).BuildTag())
                    }).BuildTag()),
                    new ImprintTag(Constants.Pdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                }).BuildTag());

            ExtendResponsePdu tag2 = new ExtendResponsePdu(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void ExtendRequestPduToStringWithErrorTest()
        {
            ExtendResponsePdu tag = new ExtendResponsePdu(new TlvTagBuilder(Constants.ExtendResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new PduHeader(new TlvTagBuilder(Constants.PduHeader.TagType, false, false,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.PduHeader.LoginIdTagType, false, false, "Test Login Id"),
                            new IntegerTag(Constants.PduHeader.InstanceIdTagType, false, false, 1),
                            new IntegerTag(Constants.PduHeader.MessageIdTagType, false, false, 2)
                        }).BuildTag()),
                    new ExtendErrorPayload(new TlvTagBuilder(Constants.ErrorPayload.TagType, false, false, new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 1),
                        new StringTag(Constants.PduPayload.ErrorMessageTagType, false, false, "Test Error message")
                    }).BuildTag()),
                    new ImprintTag(Constants.Pdu.MacTagType, false, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                }).BuildTag());

            ExtendResponsePdu tag2 = new ExtendResponsePdu(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }

        [Test]
        public void InvalidExtendPduHeaderNotFirst()
        {
            Assert.That(delegate
                {
                    new ExtendResponsePdu(new TlvTagBuilder(Constants.ExtendResponsePdu.TagType, false, false,
                        new ITlvTag[]
                        {
                            new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false, new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                                new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                                new StringTag(Constants.PduPayload.ErrorMessageTagType, false, false, "Test error message."),
                                new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 1),
                                new CalendarHashChain(new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1),
                                        new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 0),
                                        new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                })),
                                        // add links
                                        new ImprintTag((uint)LinkDirection.Left, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                }))
                                    }).BuildTag())
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
                "Creating ExtendPdu should fail when header is not the first element.");
        }

        [Test]
        public void InvalidExtendPduMacNotLast()
        {
            Assert.That(delegate
                {
                    new ExtendResponsePdu(new TlvTagBuilder(Constants.ExtendResponsePdu.TagType, false, false,
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
                            new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false, new ITlvTag[]
                            {
                                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                                new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                                new StringTag(Constants.PduPayload.ErrorMessageTagType, false, false, "Test error message."),
                                new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 1),
                                new CalendarHashChain(new TlvTagBuilder(Constants.CalendarHashChain.TagType, false, false,
                                    new ITlvTag[]
                                    {
                                        new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1),
                                        new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 0),
                                        new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                })),
                                        // add links
                                        new ImprintTag((uint)LinkDirection.Left, false, false,
                                            new DataHash(HashAlgorithm.Sha2256,
                                                new byte[]
                                                {
                                                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                                                }))
                                    }).BuildTag())
                            }).BuildTag()),
                        }).BuildTag());
                }, Throws.Exception.TypeOf<TlvException>().With.Message.StartWith("MAC must be the last element"),
                "Creating ExtendPdu should fail when mac is not the last element.");
        }
    }
}