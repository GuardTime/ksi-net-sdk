using System;
using System.IO;
using System.Threading;
using Guardtime.KSI.Parser;
using NUnit.Framework;

namespace Guardtime.KSI.Service
{
    public class TestKsiServiceProtocol : IKsiSigningServiceProtocol, IKsiExtendingServiceProtocol, IKsiPublicationsFileServiceProtocol
    {
        public bool FailNext { get; set; }

        public IAsyncResult BeginSign(byte[] data, AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(data);
        }

        public byte[] EndSign(IAsyncResult asyncResult)
        {
            AsyncResult result = (AsyncResult)asyncResult;

            using (TlvReader reader = new TlvReader(new MemoryStream(result.Request)))
            {
                AggregationPdu pdu = new AggregationPdu(reader.ReadTag());
                AggregationRequestPayload payload = pdu.Payload as AggregationRequestPayload;
                Assert.IsNotNull(payload);
            }

            return null;
        }

        public IAsyncResult BeginExtend(byte[] data, AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(data);
        }

        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            AsyncResult result = (AsyncResult)asyncResult;

            using (TlvReader reader = new TlvReader(new MemoryStream(result.Request)))
            {
                ExtendPdu pdu = new ExtendPdu(reader.ReadTag());
                ExtendRequestPayload payload = (ExtendRequestPayload)pdu.Payload;
                string filename = "response-" + (FailNext ? "invalid" : "ok") + "-anon-";
                FailNext = false;

                return payload.PublicationTime == null
                    ? ReadFile("resources/extender-response/" + filename + payload.AggregationTime + ".tlv")
                    : ReadFile("resources/extender-response/" + filename + payload.AggregationTime + "-" + payload.PublicationTime + ".tlv");
            }
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
            using (FileStream stream = new FileStream(file, FileMode.Open))
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