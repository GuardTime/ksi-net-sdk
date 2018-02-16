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
using System.Reflection;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class ExtendResponsePayloadTests
    {
        [Test]
        public void ExtendResponsePayloadTest()
        {
            ExtendResponsePayload payload = new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 1),
                    new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                    new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 3),
                }).BuildTag());

            Assert.AreEqual(1, payload.Status, "Unexpected status");
            Assert.AreEqual(2, payload.RequestId, "Unexpected request id");
            Assert.AreEqual(3, payload.CalendarLastTime, "Unexpected calendar last time");
        }

        [Test]
        public void ExtendResponsePayloadWithoutStatusCode()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one status code must exist in response payload."));
        }

        [Test]
        public void ExtendResponsePayloadWithMultipleErrors()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                        new StringTag(Constants.PduPayload.ErrorMessageTagType, false, false, "Test error message 1."),
                        new StringTag(Constants.PduPayload.ErrorMessageTagType, false, false, "Test error message 2."),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one error message is allowed in response payload"));
        }

        [Test]
        public void ExtendResponsePayloadWithoutRequestId()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one request id must exist in response payload"));
        }

        [Test]
        public void ExtendResponsePayloadWithMultipleCalendarLastTimes()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                        new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                        new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 1),
                        new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one calendar last time is allowed in extend response payload"));
        }

        [Test]
        public void ExtendResponsePayloadWithoutCalendarHashChain()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendResponsePayload(new TlvTagBuilder(Constants.ExtendResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                        new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one calendar hash chain must exist in extend response payload"));
        }

        [Test]
        public void ToStringTest()
        {
            Assembly assembly = typeof(AggregationHashChain).Assembly;
            Type linkType = assembly.GetType("Guardtime.KSI.Signature.CalendarHashChain+Link");

            ExtendResponsePayload tag = TestUtil.GetCompositeTag<ExtendResponsePayload>(Constants.ExtendResponsePayload.TagType, new ITlvTag[]
            {
                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 2),
                new IntegerTag(Constants.PduPayload.StatusTagType, false, false, 0),
                new StringTag(Constants.PduPayload.ErrorMessageTagType, false, false, "Test error message."),
                new IntegerTag(Constants.ExtendResponsePayload.CalendarLastTimeTagType, false, false, 1),
                TestUtil.GetCompositeTag<CalendarHashChain>(Constants.CalendarHashChain.TagType,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.CalendarHashChain.PublicationTimeTagType, false, false, 1),
                        new IntegerTag(Constants.CalendarHashChain.AggregationTimeTagType, false, false, 0),
                        new ImprintTag(Constants.CalendarHashChain.InputHashTagType, false, false,
                            new DataHash(HashAlgorithm.Sha2256,
                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                        // add links
                        (ITlvTag)Activator.CreateInstance(linkType, new ImprintTag((uint)LinkDirection.Left, false, false,
                            new DataHash(HashAlgorithm.Sha2256,
                                new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })))
                    })
            });

            ExtendResponsePayload tag2 = new ExtendResponsePayload(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}