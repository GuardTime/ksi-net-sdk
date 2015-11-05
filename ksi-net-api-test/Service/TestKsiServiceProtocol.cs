using System;
using System.IO;
using System.Text;
using System.Threading;
using Guardtime.KSI.Parser;
using Guardtime.KSI.Signature;

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
            var result = (AsyncResult)asyncResult;

            using (var stream = new MemoryStream(result.Request))
            {
                using (var reader = new TlvReader(stream))
                {
                    var pdu = new AggregationPdu(reader.ReadTag());
                    var payload = (AggregationRequestPayload)pdu.Payload;
                    // TODO: Get stuff based on hash
                    //payload.RequestHash
                }
            }

            return null;
        }

        public IAsyncResult BeginExtend(byte[] data, AsyncCallback callback, object asyncState)
        {
            return new AsyncResult(data);
        }

        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            var result = (AsyncResult)asyncResult;

            using (var stream = new MemoryStream(result.Request))
            {
                using (var reader = new TlvReader(stream))
                {
                    var pdu = new ExtendPdu(reader.ReadTag());
                    var payload = (ExtendRequestPayload)pdu.Payload;
                    var filename = "response-" + (FailNext ? "invalid" : "ok") + "-anon-";
                    FailNext = false;

                    if (payload.PublicationTime == null)
                    {
                        return ReadFile("resources/extender-response/" + filename + payload.AggregationTime + ".tlv");
                    }

                    return ReadFile("resources/extender-response/" + filename + payload.AggregationTime + "-" + payload.PublicationTime + ".tlv");
                }
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
            using (var stream = new FileStream(file, FileMode.Open))
            {
                var data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);

                return data;
            }
        }

        private class AsyncResult : IAsyncResult
        {
            ManualResetEvent resetEvent = new ManualResetEvent(true);

            public AsyncResult(byte[] request)
            {
                Request = request;
            }

            public bool IsCompleted
            {
                get { return true; }
            }

            public byte[] Request { get; set; }

            public WaitHandle AsyncWaitHandle
            {
                get { return resetEvent; }
            }

            public object AsyncState
            {
                get { return null; }
            }

            public bool CompletedSynchronously
            {
                get { return true; }
            }
        }
    }
}