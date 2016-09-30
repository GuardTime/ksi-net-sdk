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

using System;
using System.IO;
using System.Threading;
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Service;
using Guardtime.KSI.Signature;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Test.Service
{
    public class TestKsiServiceProtocol : IKsiSigningServiceProtocol, IKsiExtendingServiceProtocol, IKsiPublicationsFileServiceProtocol
    {
        public IKsiSignature SignResult { get; set; }
        public CalendarHashChain ExtendResult { get; set; }

        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(data);
        }

        public byte[] EndSign(IAsyncResult asyncResult)
        {
            AggregationResponsePayload payload;
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new IntegerTag(Constants.AggregationResponsePayload.RequestIdTagType, false, false, 2));
                writer.WriteTag(new IntegerTag(Constants.KsiPduPayload.StatusTagType, false, false, 0));

                foreach (ITlvTag childTag in SignResult)
                {
                    if (childTag.Type > 0x800 && childTag.Type < 0x900)
                    {
                        writer.WriteTag(childTag);
                    }
                }

                payload = new AggregationResponsePayload(new RawTag(Constants.AggregationResponsePayload.TagType, false, false,
                    ((MemoryStream)writer.BaseStream).ToArray()));
            }

            KsiPduHeader header = new KsiPduHeader("test");

            AggregationPdu pdu = new AggregationPdu(header, payload, KsiPdu.GetHashMacTag(HashAlgorithm.Default, Util.EncodeNullTerminatedUtf8String("test"), header, payload));

            return pdu.Encode();
        }

        public IAsyncResult BeginExtend(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(data);
        }

        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            ExtendResponsePayload payload;
            using (TlvWriter writer = new TlvWriter(new MemoryStream()))
            {
                writer.WriteTag(new IntegerTag(Constants.ExtendResponsePayload.RequestIdTagType, false, false, 2));
                writer.WriteTag(new IntegerTag(Constants.KsiPduPayload.StatusTagType, false, false, 0));
                writer.WriteTag(ExtendResult);

                payload = new ExtendResponsePayload(new RawTag(Constants.ExtendResponsePayload.TagType, false, false,
                    ((MemoryStream)writer.BaseStream).ToArray()));
            }

            KsiPduHeader header = new KsiPduHeader("test");

            ExtendPdu pdu = new ExtendPdu(header, payload, KsiPdu.GetHashMacTag(HashAlgorithm.Default, Util.EncodeNullTerminatedUtf8String("test"), header, payload));

            return pdu.Encode();
        }

        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(null);
        }

        public byte[] EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            // TODO: use variable
            return ReadFile("resources/publication/publicationsfile/ksi-publications.bin");
        }

        private static byte[] ReadFile(string file)
        {
            using (FileStream stream = new FileStream(Path.Combine(TestSetup.LocalPath, file), FileMode.Open))
            {
                byte[] data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);

                return data;
            }
        }

        private class AsyncResult : IAsyncResult, IDisposable
        {
            private readonly ManualResetEvent _resetEvent = new ManualResetEvent(true);

            public AsyncResult(byte[] request)
            {
                Request = request;
            }

            public bool IsCompleted => true;

            public byte[] Request { get; }

            public WaitHandle AsyncWaitHandle => _resetEvent;

            public object AsyncState => null;

            public bool CompletedSynchronously => true;

            public void Dispose()
            {
                _resetEvent.Dispose();
            }
        }
    }
}