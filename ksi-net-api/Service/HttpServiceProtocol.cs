using System;
using System.IO;
using System.Net;
using System.Threading;

namespace Guardtime.KSI.Service
{

    // TODO: Make thread safe
    // TODO: Should be possible to set timeout

    // TODO: Better names
    public class HttpKsiServiceProtocol : IKsiServiceProtocol
    {
        // Require settings
        public HttpKsiServiceProtocol()
        {
        }

        // TODO: Better name
        private void EndAsyncGetRequestStreamCallback(IAsyncResult asyncResult)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = asyncResult.AsyncState as HttpKsiServiceProtocolAsyncResult;
            if (httpAsyncResult == null)
            {
                // TODO: Should not happen
                throw new InvalidCastException("httpAsyncResult");
            }

            byte[] data = httpAsyncResult.PostData;
            Stream stream = httpAsyncResult.Request.EndGetRequestStream(asyncResult);
            stream.Write(data, 0, data.Length);
            stream.Close();

            httpAsyncResult.ResponseAsyncResult = httpAsyncResult.Request.BeginGetResponse(EndAsyncGetResponseCallback, httpAsyncResult);
        }

        // TODO: Better name
        private void EndAsyncGetResponseCallback(IAsyncResult asyncResult)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = asyncResult.AsyncState as HttpKsiServiceProtocolAsyncResult;
            if (httpAsyncResult == null)
            {
                // TODO: Should not happen
                throw new InvalidCastException("httpAsyncResult");
            }

            httpAsyncResult.SetComplete();
        }

        

        public IAsyncResult BeginCreateSignature(byte[] data, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }
            // TODO: URLs from conf
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://ksigw.test.guardtime.com:3333/gt-signingservice");

            // TODO: Seems to work with expect100
            //request.ServicePoint.Expect100Continue = false;
            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, callback);
            httpAsyncResult.StreamAsyncResult = request.BeginGetRequestStream(EndAsyncGetRequestStreamCallback, httpAsyncResult);
            return httpAsyncResult;
        }

        public byte[] EndCreateSignature(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        public IAsyncResult BeginExtendSignature(byte[] data, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            WebRequest request = WebRequest.Create("http://ksigw.test.guardtime.com:8010/gt-extendingservice");
            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, callback);
            httpAsyncResult.StreamAsyncResult = request.BeginGetRequestStream(EndAsyncGetRequestStreamCallback, httpAsyncResult);
            return httpAsyncResult;
        }

        public byte[] EndExtendSignature(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            WebRequest request = WebRequest.Create("http://verify.guardtime.com/ksi-publications.bin");
            request.Method = WebRequestMethods.Http.Get;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, null, callback);
            httpAsyncResult.ResponseAsyncResult = request.BeginGetResponse(EndAsyncGetResponseCallback, httpAsyncResult);
            return httpAsyncResult;
        }

        public byte[] EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        private byte[] EndGetResult(IAsyncResult asyncResult)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = asyncResult as HttpKsiServiceProtocolAsyncResult;
            if (httpAsyncResult == null)
            {
                // TODO: Better name
                throw new InvalidCastException("httpAsyncResult");
            }

            if (!httpAsyncResult.IsCompleted)
            {
                httpAsyncResult.AsyncWaitHandle.WaitOne();
            }

            // TODO: Make buffer configurable
            byte[] buffer = new byte[8092];
            try
            {
                WebResponse response = httpAsyncResult.Request.EndGetResponse(httpAsyncResult.ResponseAsyncResult);
                if (response == null)
                {
                    // TODO: When response is empty
                    throw new Exception("Problem");
                }

                //TODO: Check java api response handling, KSISignatureDO when handles list then skips unnessessary tags, in other constructors will give error
                using (Stream s = response.GetResponseStream())
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int bytesLength;
                    while ((bytesLength = s.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        memoryStream.Write(buffer, 0, bytesLength);
                    }

                    return memoryStream.ToArray();
                }
            }
            catch (WebException e)
            {
                if (e.Response == null)
                {
                    // TODO: Correct exception
                    throw new Exception("Response message missing", e);
                }

                using (Stream s = e.Response.GetResponseStream())
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int bytesLength;
                    while ((bytesLength = s.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        memoryStream.Write(buffer, 0, bytesLength);
                    }

                    return memoryStream.ToArray();
                }
            }
            catch (Exception e)
            {
                // TODO: Handle exception
                throw;
            }
        }

        private class HttpKsiServiceProtocolAsyncResult : IAsyncResult
        {
            private bool _isCompleted;
            private bool _isCompletedSynchronously;
            private readonly ManualResetEvent _waitHandle;
            private object _asyncState;

            private readonly AsyncCallback _callback;

            private readonly object _lock;

            private IAsyncResult _streamAsyncResult;
            private IAsyncResult _responseAsyncResult;

            private readonly WebRequest _request;
            private readonly byte[] _postData;

            // TODO: Set state
            public HttpKsiServiceProtocolAsyncResult(WebRequest request, byte[] postData, AsyncCallback callback)
            {
                if (request == null)
                {
                    throw new ArgumentNullException("request");
                }

                _request = request;
                _postData = postData;
                _callback = callback;

                _isCompleted = false;
                _isCompletedSynchronously = false;

                _lock = new object();
                _waitHandle = new ManualResetEvent(false);
            }

            public object AsyncState
            {
                get
                {
                    return _asyncState;
                }
            }

            public WaitHandle AsyncWaitHandle
            {
                get
                {
                    return _waitHandle;
                }
            }

            public bool CompletedSynchronously
            {
                get
                {
                    lock (_lock)
                    {
                        return _isCompletedSynchronously;
                    }
                }
            }

            public bool IsCompleted
            {
                get
                {
                    lock (_lock)
                    {
                        return _isCompleted;
                    }
                }
            }

            public IAsyncResult StreamAsyncResult
            {
                get
                {
                    return _streamAsyncResult;
                }

                set
                {
                    _streamAsyncResult = value;
                }
            }

            public IAsyncResult ResponseAsyncResult
            {
                get
                {
                    return _responseAsyncResult;
                }

                set
                {
                    _responseAsyncResult = value;
                }
            }

            public WebRequest Request
            {
                get
                {
                    return _request;
                }
            }

            public byte[] PostData
            {
                get
                {
                    return _postData;
                }
            }

            public void SetComplete()
            {

                lock (_lock)
                {
                    if (!_isCompleted)
                    {
                        _isCompleted = true;
                        _isCompletedSynchronously = true;
                        if (_callback != null)
                        {
                            _callback.Invoke(this);
                        }
                    }
                }

                if (!_waitHandle.Set())
                {
                    // TODO: Should not happen
                    throw new Exception("WaitHandle completion failed");
                }
            }
        }
    }

    
}
