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

using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using NUnit.Framework;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class AggregatorConfigResponsePayloadTests
    {
        [Test]
        public void AggregatorConfigResponsePayloadOk()
        {
            AggregatorConfigResponsePayload conf = new AggregatorConfigResponsePayload(new TlvTagBuilder(Constants.AggregatorConfigResponsePayload.TagType, false, false,
                new ITlvTag[]
                {
                    new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxLevelTagType, false, false, 1),
                    new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationAlgorithmTagType, false, false, 2),
                    new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationPeriodTagType, false, false, 3),
                    new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxRequestsTagType, false, false, 4),
                }).BuildTag());

            Assert.AreEqual(1, conf.MaxLevel, "Unexpected max requests");
            Assert.AreEqual(2, conf.AggregationAlgorithm, "Unexpected calendar first time");
            Assert.AreEqual(3, conf.AggregationPeriod, "Unexpected calendar last time");
            Assert.AreEqual(4, conf.MaxRequests, "Unexpected max requests");
        }

        [Test]
        public void AggregatorConfigResponsePayloadWithMultipleMaxLevels()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregatorConfigResponsePayload(new TlvTagBuilder(Constants.AggregatorConfigResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxLevelTagType, false, false, 1),
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxLevelTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one max level tag is allowed in aggregator config response payload."));
        }

        [Test]
        public void AggregatorConfigResponsePayloadWithMultipleAggregationAlgorithms()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregatorConfigResponsePayload(new TlvTagBuilder(Constants.AggregatorConfigResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationAlgorithmTagType, false, false, 1),
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationAlgorithmTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one aggregation algorithm tag is allowed in aggregator config response payload"));
        }

        [Test]
        public void AggregatorConfigResponsePayloadWithMultipleAggregationPeriods()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregatorConfigResponsePayload(new TlvTagBuilder(Constants.AggregatorConfigResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationPeriodTagType, false, false, 1),
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.AggregationPeriodTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one aggregation period tag is allowed in aggregator config response payload"));
        }

        [Test]
        public void AggregatorConfigResponsePayloadWithMultipleMaxRequests()
        {
            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                new AggregatorConfigResponsePayload(new TlvTagBuilder(Constants.AggregatorConfigResponsePayload.TagType, false, false,
                    new ITlvTag[]
                    {
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxRequestsTagType, false, false, 1),
                        new IntegerTag(Constants.AggregatorConfigResponsePayload.MaxRequestsTagType, false, false, 2),
                    }).BuildTag());
            });

            Assert.That(ex.Message, Does.StartWith("Only one max requests tag is allowed in aggregator config response payload."));
        }
    }
}