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

using System.IO;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service.Tcp;
using Guardtime.KSI.Test.Parser;
using Guardtime.KSI.Utils;
using NUnit.Framework;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Test.Service
{
    [TestFixture]
    public class TcpResponseProcessorTests
    {
        /// <summary>
        /// TCP response processor test with aggregation response payload.
        /// </summary>
        [Test]
        public void TcpProcessorAggregationOkTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            asyncResultCollection.Add(123, new TcpKsiServiceAsyncResult(TcpRequestType.Aggregation, null, 123, null, null));

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            CompositeTestTag pdu = new CompositeTestTag(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.AggregationResponsePayload.TagType, true, false, new ITlvTag[] { new IntegerTag(0x1, true, false, 123), }),
                });

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(pdu);
                byte[] data = ((MemoryStream)writer.BaseStream).ToArray();
                processor.ProcessReceivedData(data, data.Length);
            }
        }

        /// <summary>
        /// TCP response processor test with aggregation response payload.
        /// </summary>
        [Test]
        public void TcpProcessorAggregationConfigOkTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            asyncResultCollection.Add(123, new TcpKsiServiceAsyncResult(TcpRequestType.AggregatorConfig, null, 123, null, null));

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            CompositeTestTag pdu = new CompositeTestTag(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.AggregatorConfigResponsePayload.TagType, true, false, new ITlvTag[] { }),
                });

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(pdu);
                byte[] data = ((MemoryStream)writer.BaseStream).ToArray();
                processor.ProcessReceivedData(data, data.Length);
            }
        }

        /// <summary>
        /// TCP response processor test with unknown non-critical TLV. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void TcpProcessorOkWithWarningTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            asyncResultCollection.Add(123, new TcpKsiServiceAsyncResult(TcpRequestType.AggregatorConfig, null, 123, null, null));

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            CompositeTestTag pdu = new CompositeTestTag(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.PduHeader.TagType, true, false,
                        new ITlvTag[]
                        {
                            new StringTag(Constants.PduHeader.LoginIdTagType, true, false, "Test Login Id"),
                            new IntegerTag(Constants.PduHeader.InstanceIdTagType, true, false, 1),
                            new IntegerTag(Constants.PduHeader.MessageIdTagType, true, false, 2)
                        }),
                    new CompositeTestTag(Constants.AggregatorConfigResponsePayload.TagType, true, false, new ITlvTag[] { }),
                    new CompositeTestTag(0xAA, true, true, new ITlvTag[] { }), // unknown tag
                    new ImprintTag(Constants.Pdu.MacTagType, true, false,
                        new DataHash(HashAlgorithm.Sha2256,
                            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 })),
                });

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(pdu);
                byte[] data = ((MemoryStream)writer.BaseStream).ToArray();
                processor.ProcessReceivedData(data, data.Length);
            }
        }

        /// <summary>
        /// TCP response processor test with aggregation response payload without request Id.
        /// </summary>
        [Test]
        public void TcpProcessorInvalidNoRequestIdTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            CompositeTestTag pdu = new CompositeTestTag(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.AggregationResponsePayload.TagType, true, false, new ITlvTag[] { }),
                });

            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(pdu);
                byte[] data = ((MemoryStream)writer.BaseStream).ToArray();
                KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
                {
                    processor.ProcessReceivedData(data, data.Length);
                });

                Assert.That(ex.Message.StartsWith("Cannot find request id tag from aggregation response payload"), "Unexpected exception message: " + ex.Message);
            }
        }

        /// <summary>
        /// TCP response processor test with unknown critical TLV.
        /// </summary>
        [Test]
        public void TcpProcessorInvalidTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);
            byte[] data = Base16.Decode("822100084302440007024400");

            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                processor.ProcessReceivedData(data, data.Length);
            });

            Assert.That(ex.Message.StartsWith("Unknown tag type (0x7)"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// TCP response processor test without known payload and with unknown non-critical TLVs. Warning about no matching request found and warning about unexpected payload are logged. 
        /// </summary>
        [Test]
        public void TcpProcessorNoKnownPayloadsTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);
            byte[] data = Base16.Decode("822100084302440067024400");
            processor.ProcessReceivedData(data, data.Length);
        }
    }
}