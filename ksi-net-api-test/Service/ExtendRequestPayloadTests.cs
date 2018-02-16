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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class ExtendRequestPayloadTests
    {
        [Test]
        public void ExtendRequestPayloadTest()
        {
            ExtendRequestPayload tag = new ExtendRequestPayload(new TlvTagBuilder(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
            {
                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, 2),
                new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, 3),
            }).BuildTag());

            Assert.AreEqual(1, tag.RequestId, "Unexpected request id");
            Assert.AreEqual(2, tag.AggregationTime, "Unexpected aggregation time");
            Assert.AreEqual(3, tag.PublicationTime, "Unexpected publication time");
        }

        [Test]
        public void ExtendRequestPayloadWithoutRequestId()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendRequestPayload(new TlvTagBuilder(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
                {
                    new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, 2),
                }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one request id must exist in extend request payload"));
        }

        [Test]
        public void ExtendRequestPayloadWithoutAggregationTime()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendRequestPayload(new TlvTagBuilder(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
                {
                    new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Exactly one aggregation time must exist in extend request payload"));
        }

        [Test]
        public void ExtendRequestPayloadWithMultiplePublicationTimes()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new ExtendRequestPayload(new TlvTagBuilder(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
                {
                    new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                    new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, 2),
                    new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, 3),
                    new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, 3),
                }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one publication time is allowed in extend request payload."));
        }

        [Test]
        public void ToStringTest()
        {
            ExtendRequestPayload tag = new ExtendRequestPayload(new TlvTagBuilder(Constants.ExtendRequestPayload.TagType, false, false, new ITlvTag[]
            {
                new IntegerTag(Constants.PduPayload.RequestIdTagType, false, false, 1),
                new IntegerTag(Constants.ExtendRequestPayload.AggregationTimeTagType, false, false, 2),
                new IntegerTag(Constants.ExtendRequestPayload.PublicationTimeTagType, false, false, 3),
            }).BuildTag());

            ExtendRequestPayload tag2 = new ExtendRequestPayload(new RawTag(tag.Type, tag.NonCritical, tag.Forward, tag.EncodeValue()));

            Assert.AreEqual(tag.ToString(), tag2.ToString());
        }
    }
}