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
using Guardtime.KSI.Service.Tcp;
using Guardtime.KSI.Test.Parser;
using Guardtime.KSI.Utils;
using NUnit.Framework;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Service;

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
            TcpKsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(KsiServiceRequestType.Sign, null, 123, null, null);
            asyncResultCollection.Add(123, asyncResult);

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.AggregationResponsePayload.TagType, true, false, new ITlvTag[] { new IntegerTag(0x1, true, false, 123), }),
                }).BuildTag().Encode();

            Assert.IsFalse(asyncResult.IsCompleted, "Async result cannot be completed.");

            processor.ProcessReceivedData(data, data.Length);
            Assert.AreEqual(0, asyncResultCollection.Count(), "Invalid Async collection count.");
            Assert.IsTrue(Util.IsArrayEqual(data, asyncResult.ResultStream.ToArray()), "Invalid async result stream content.");
            Assert.IsTrue(asyncResult.IsCompleted, "Async result must be completed.");
        }

        /// <summary>
        /// TCP response processor test with extending response payload.
        /// </summary>
        [Test]
        public void TcpProcessorExtendingOkTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpKsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(KsiServiceRequestType.Extend, null, 123, null, null);
            asyncResultCollection.Add(123, asyncResult);

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.ExtendResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.ExtendResponsePayload.TagType, true, false, new ITlvTag[] { new IntegerTag(0x1, true, false, 123), }),
                }).BuildTag().Encode();

            Assert.IsFalse(asyncResult.IsCompleted, "Async result cannot be completed.");

            processor.ProcessReceivedData(data, data.Length);

            Assert.AreEqual(0, asyncResultCollection.Count(), "Invalid Async collection count.");
            Assert.IsTrue(Util.IsArrayEqual(data, asyncResult.ResultStream.ToArray()), "Invalid async result stream content.");
            Assert.IsTrue(asyncResult.IsCompleted, "Async result must be completed.");
        }

        /// <summary>
        /// TCP response processor test with aggregation response payload.
        /// </summary>
        [Test]
        public void TcpProcessorAggregationConfigOkTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpKsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(KsiServiceRequestType.AggregatorConfig, null, 123, null, null);
            asyncResultCollection.Add(123, asyncResult);

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.AggregatorConfigResponsePayload.TagType, true, false, new ITlvTag[] { }),
                }).BuildTag().Encode();

            processor.ProcessReceivedData(data, data.Length);

            Assert.AreEqual(0, asyncResultCollection.Count(), "Invalid Async collection count.");
            Assert.IsTrue(Util.IsArrayEqual(data, asyncResult.ResultStream.ToArray()), "Invalid async result stream content.");
            Assert.IsTrue(asyncResult.IsCompleted, "Async result must be completed.");
        }

        /// <summary>
        /// TCP response processor test with aggregation response payload.
        /// </summary>
        [Test]
        public void TcpProcessorExtenderConfigOkTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpKsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(KsiServiceRequestType.ExtenderConfig, null, 123, null, null);
            asyncResultCollection.Add(123, asyncResult);

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.ExtendResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.ExtenderConfigResponsePayload.TagType, true, false, new ITlvTag[] { }),
                }).BuildTag().Encode();

            processor.ProcessReceivedData(data, data.Length);

            Assert.AreEqual(0, asyncResultCollection.Count(), "Invalid Async collection count.");
            Assert.IsTrue(Util.IsArrayEqual(data, asyncResult.ResultStream.ToArray()), "Invalid async result stream content.");
            Assert.IsTrue(asyncResult.IsCompleted, "Async result must be completed.");
        }

        /// <summary>
        /// TCP response processor test with unknown non-critical TLV. Warning about unexpected payload is logged.
        /// </summary>
        [Test]
        public void TcpProcessorOkWithUnknownNonCriticalTlvTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpKsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(KsiServiceRequestType.AggregatorConfig, null, 123, null, null);
            asyncResultCollection.Add(123, asyncResult);

            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.AggregationResponsePdu.TagType, false, false,
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
                }).BuildTag().Encode();

            processor.ProcessReceivedData(data, data.Length);
            Assert.IsTrue(Util.IsArrayEqual(data, asyncResult.ResultStream.ToArray()), "Invalid async result stream content.");

            Assert.AreEqual(0, asyncResultCollection.Count(), "Invalid Async collection count.");
            Assert.IsTrue(Util.IsArrayEqual(data, asyncResult.ResultStream.ToArray()), "Invalid async result stream content.");
            Assert.IsTrue(asyncResult.IsCompleted, "Async result must be completed.");
        }

        /// <summary>
        /// TCP response processor test with unknown critical TLV. Exceptions is thrown.
        /// </summary>
        [Test]
        public void TcpProcessorInvalidWithUnknownCriticalTlvTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);
            byte[] data =
                Base16.Decode(
                    // 01 - header, 67 - unknown critical, 04 - aggr config, 1F - mac
                    "8221004A 01120105616E6F6E0002045809EBFA030331926A 070101 040E0101110201010302019004020400 1F21012526C7B579BFB93263BDFE421CB29A8AFE81C65E9C8773CBAD8AC691B3C2A89C"
                        .Replace(" ", ""));

            TlvException ex = Assert.Throws<TlvException>(delegate
            {
                processor.ProcessReceivedData(data, data.Length);
            });

            Assert.That(ex.Message.StartsWith("Unknown tag type (0x7)"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// TCP response processor test with aggregation response payload without request Id.
        /// </summary>
        [Test]
        public void TcpProcessorInvalidNoRequestIdTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.AggregationResponsePayload.TagType, true, false, new ITlvTag[] { }),
                }).BuildTag().Encode();

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                processor.ProcessReceivedData(data, data.Length);
            });

            Assert.That(ex.Message.StartsWith("Cannot find request id tag from aggregation response payload"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// TCP response processor test with aggregation response payload without request Id.
        /// </summary>
        [Test]
        public void TcpProcessorAggregationResponseInvalidNoRequestIdTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.AggregationResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.AggregationResponsePayload.TagType, true, false, new ITlvTag[] { }),
                }).BuildTag().Encode();

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                processor.ProcessReceivedData(data, data.Length);
            });

            Assert.That(ex.Message.StartsWith("Cannot find request id tag from aggregation response payload"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// TCP response processor test with extend response payload without request Id.
        /// </summary>
        [Test]
        public void TcpProcessorExtendResponseInvalidNoRequestIdTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.ExtendResponsePdu.TagType, false, false,
                new ITlvTag[]
                {
                    new CompositeTestTag(Constants.ExtendResponsePayload.TagType, true, false, new ITlvTag[] { }),
                }).BuildTag().Encode();

            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                processor.ProcessReceivedData(data, data.Length);
            });

            Assert.That(ex.Message.StartsWith("Cannot find request id tag from extender response payload"), "Unexpected exception message: " + ex.Message);
        }

        /// <summary>
        /// TCP response processor test with PDU without a payload. Warning is logged: "Could not get payload from response PDU"
        /// </summary>
        [Test]
        public void TcpProcessorInvalidNoPayloadTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpKsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(KsiServiceRequestType.AggregatorConfig, null, 123, null, null);
            asyncResultCollection.Add(123, asyncResult);
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new TlvTagBuilder(Constants.AggregationResponsePdu.TagType, false, false, new ITlvTag[] { }).BuildTag().Encode();
            processor.ProcessReceivedData(data, data.Length);

            Assert.AreEqual(1, asyncResultCollection.Count(), "Invalid Async collection count.");
            Assert.AreEqual(0, asyncResult.ResultStream.Length, "Invalid async result stream content.");
            Assert.IsFalse(asyncResult.IsCompleted, "Async result must not be completed.");
        }

        /// <summary>
        /// TCP response processor test with unknonw response PDU type.
        /// </summary>
        [Test]
        public void TcpProcessorUnknowndResponsePduTypeTest()
        {
            TcpAsyncResultCollection asyncResultCollection = new TcpAsyncResultCollection();
            TcpResponseProcessor processor = new TcpResponseProcessor(asyncResultCollection);

            byte[] data = new StringTag(0, false, false, "asdf").Encode();
            KsiServiceProtocolException ex = Assert.Throws<KsiServiceProtocolException>(delegate
            {
                processor.ProcessReceivedData(data, data.Length);
            });

            Assert.That(ex.Message.StartsWith("Unknown response PDU type"), "Unexpected exception message: " + ex.Message);
        }
    }
}