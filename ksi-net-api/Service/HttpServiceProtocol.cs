using System;
using System.IO;
using System.Net;
using System.Threading;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     HTTP KSI service protocol.
    /// </summary>
    public class HttpKsiServiceProtocol : IKsiSigningServiceProtocol, IKsiExtendingServiceProtocol,
        IKsiPublicationsFileServiceProtocol
    {
        private readonly int _bufferSize = 8092;
        private readonly string _extendingUrl;
        private readonly string _publicationsFileUrl;
        private readonly int _requestTimeOut = 100000;

        private readonly string _signingUrl;


        /// <summary>
        ///     Create HTTP KSI service protocol with given url-s
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="extendingUrl">extending url</param>
        /// <param name="publicationsFileUrl">publications file url</param>
        public HttpKsiServiceProtocol(string signingUrl, string extendingUrl, string publicationsFileUrl)
        {
            _signingUrl = signingUrl;
            _extendingUrl = extendingUrl;
            _publicationsFileUrl = publicationsFileUrl;
        }

        /// <summary>
        ///     Create HTTP KSI service protocol with given url-s and request timeout
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="extendingUrl">extending url</param>
        /// <param name="publicationsFileUrl">publications file url</param>
        /// <param name="requestTimeout">request timeout</param>
        public HttpKsiServiceProtocol(string signingUrl, string extendingUrl, string publicationsFileUrl,
            int requestTimeout) : this(signingUrl, extendingUrl, publicationsFileUrl)
        {
            if (requestTimeout < 0)
            {
                throw new KsiServiceProtocolException("Request timeout should be in milliseconds, but was (" +
                                                      requestTimeout + ").");
            }
            _requestTimeOut = requestTimeout;
        }

        /// <summary>
        ///     Create HTTP KSI service protocol with given url-s, request timeout and buffer size
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="extendingUrl">extending url</param>
        /// <param name="publicationsFileUrl">publications file url</param>
        /// <param name="requestTimeout">request timeout</param>
        /// <param name="bufferSize">buffer size</param>
        public HttpKsiServiceProtocol(string signingUrl, string extendingUrl, string publicationsFileUrl,
            int requestTimeout, int bufferSize) : this(signingUrl, extendingUrl, publicationsFileUrl, requestTimeout)
        {
            if (bufferSize < 0)
            {
                throw new KsiServiceProtocolException("Buffer size should be in positive integer, but was (" +
                                                      bufferSize + ").");
            }
            _bufferSize = bufferSize;
        }

        /// <summary>
        ///     Begin extend signature.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginExtend(byte[] data, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new KsiException("Invalid input data: null.");
            }

            HttpWebRequest request = WebRequest.Create(_extendingUrl) as HttpWebRequest;
            if (request == null)
            {
                throw new KsiServiceProtocolException("Invalid extending HTTP URL(\"" + _extendingUrl + "\").");
            }

            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data,
                callback, asyncState);
            httpAsyncResult.StreamAsyncResult = request.BeginGetRequestStream(null, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.StreamAsyncResult.AsyncWaitHandle,
                EndAsyncGetRequestStreamCallback, httpAsyncResult, _requestTimeOut, true);
            return httpAsyncResult;
        }

        /// <summary>
        ///     End extend signature.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>extending response bytes</returns>
        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        ///     Begin get publications file.
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            HttpWebRequest request = WebRequest.Create(_publicationsFileUrl) as HttpWebRequest;
            if (request == null)
            {
                throw new KsiServiceProtocolException("Invalid publications file HTTP URL(\"" + _publicationsFileUrl +
                                                      "\").");
            }

            request.Method = WebRequestMethods.Http.Get;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, null,
                callback, asyncState);
            httpAsyncResult.ResponseAsyncResult = request.BeginGetResponse(null, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.ResponseAsyncResult.AsyncWaitHandle,
                EndAsyncGetResponseCallback, httpAsyncResult, _requestTimeOut, true);

            return httpAsyncResult;
        }

        /// <summary>
        ///     End get publications file.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>publications file bytes</returns>
        public byte[] EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        ///     Begin create signature.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginSign(byte[] data, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new KsiException("Invalid input data: null.");
            }

            HttpWebRequest request = WebRequest.Create(_signingUrl) as HttpWebRequest;
            if (request == null)
            {
                throw new KsiServiceProtocolException("Invalid signing HTTP URL(\"" + _signingUrl + "\").");
            }

            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data,
                callback, asyncState);
            httpAsyncResult.StreamAsyncResult = request.BeginGetRequestStream(null, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.StreamAsyncResult.AsyncWaitHandle,
                EndAsyncGetRequestStreamCallback, httpAsyncResult, _requestTimeOut, true);
            return httpAsyncResult;
        }

        /// <summary>
        ///     End create signature.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>aggregation response bytes</returns>
        public byte[] EndSign(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }


        private void EndAsyncGetRequestStreamCallback(object state, bool timedOut)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = (HttpKsiServiceProtocolAsyncResult) state;


            if (timedOut)
            {
                httpAsyncResult.Error = new KsiServiceProtocolException("Request stream timed out.");
                httpAsyncResult.SetComplete(true);
                return;
            }


            int timeRemaining = _requestTimeOut - httpAsyncResult.TimeElapsed;
            if (timeRemaining < 0)
            {
                httpAsyncResult.Error = new KsiServiceProtocolException("Request timed out.");
                httpAsyncResult.SetComplete(true);
                return;
            }

            httpAsyncResult.Request.Timeout = _requestTimeOut;
            byte[] data = httpAsyncResult.PostData;
            try
            {
                Stream stream = httpAsyncResult.Request.EndGetRequestStream(httpAsyncResult.StreamAsyncResult);
                stream.Write(data, 0, data.Length);
                stream.Close();

                httpAsyncResult.ResponseAsyncResult = httpAsyncResult.Request.BeginGetResponse(null, httpAsyncResult);
                ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.ResponseAsyncResult.AsyncWaitHandle,
                    EndAsyncGetResponseCallback, httpAsyncResult, timeRemaining, true);
            }
            catch (Exception e)
            {
                httpAsyncResult.Error =
                    new KsiServiceProtocolException("Request failed with following error \"" + e + "\".", e);
                httpAsyncResult.SetComplete(true);
            }
        }

        private void EndAsyncGetResponseCallback(object state, bool timedOut)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult =
                (HttpKsiServiceProtocolAsyncResult) state;

            if (timedOut)
            {
                httpAsyncResult.Error = new KsiServiceProtocolException("Request timed out.");
            }

            httpAsyncResult.SetComplete(timedOut);
        }

        /// <summary>
        ///     End get result from web request.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>result bytes</returns>
        private byte[] EndGetResult(IAsyncResult asyncResult)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = asyncResult as HttpKsiServiceProtocolAsyncResult;
            if (httpAsyncResult == null)
            {
                throw new KsiServiceProtocolException("Invalid IAsyncResult.");
            }

            if (!httpAsyncResult.IsCompleted)
            {
                httpAsyncResult.AsyncWaitHandle.WaitOne();
            }

            if (httpAsyncResult.IsErroneous)
            {
                throw httpAsyncResult.Error;
            }

            byte[] buffer = new byte[_bufferSize];
            try
            {
                using (
                    WebResponse response = httpAsyncResult.Request.EndGetResponse(httpAsyncResult.ResponseAsyncResult))
                using (Stream s = response.GetResponseStream())
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int bytesLength;
                    while (s != null && (bytesLength = s.Read(buffer, 0, buffer.Length)) > 0)
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
                    throw new KsiServiceProtocolException("Error occured while trying to get response.", e);
                }

                using (Stream s = e.Response.GetResponseStream())
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int bytesLength;
                    while (s != null && (bytesLength = s.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        memoryStream.Write(buffer, 0, bytesLength);
                    }

                    return memoryStream.ToArray();
                }
            }
        }

        /// <summary>
        ///     HTTP KSI service protocol async result.
        /// </summary>
        private class HttpKsiServiceProtocolAsyncResult : IAsyncResult, IDisposable
        {
            private readonly object _asyncState;

            private readonly AsyncCallback _callback;
            private readonly object _lock;
            private readonly byte[] _postData;

            private readonly HttpWebRequest _request;

            private readonly DateTime _startTime = DateTime.Now;
            private readonly ManualResetEvent _waitHandle;
            private Exception _error;
            private bool _isCompleted;
            private bool _isCompletedSynchronously;
            private IAsyncResult _responseAsyncResult;

            private IAsyncResult _streamAsyncResult;

            public HttpKsiServiceProtocolAsyncResult(HttpWebRequest request, byte[] postData, AsyncCallback callback,
                object asyncState)
            {
                if (request == null)
                {
                    throw new KsiException("Invalid HTTP web request: null.");
                }

                _request = request;
                _postData = postData;
                _callback = callback;
                _asyncState = asyncState;

                _isCompleted = false;
                _isCompletedSynchronously = false;

                _lock = new object();
                _waitHandle = new ManualResetEvent(false);
            }

            public IAsyncResult StreamAsyncResult
            {
                get { return _streamAsyncResult; }

                set
                {
                    if (value == null)
                    {
                        throw new KsiException("Invalid IAsyncResult: null.");
                    }
                    _streamAsyncResult = value;
                }
            }

            public IAsyncResult ResponseAsyncResult
            {
                get { return _responseAsyncResult; }

                set
                {
                    if (value == null)
                    {
                        throw new KsiException("Invalid IAsyncResult: null.");
                    }
                    _responseAsyncResult = value;
                }
            }

            public HttpWebRequest Request
            {
                get { return _request; }
            }

            public byte[] PostData
            {
                get { return _postData; }
            }

            public int TimeElapsed
            {
                get { return (int) (DateTime.Now - _startTime).TotalMilliseconds; }
            }

            public bool IsErroneous
            {
                get { return _error != null; }
            }

            public Exception Error
            {
                get { return _error; }
                set { _error = value; }
            }

            public object AsyncState
            {
                get { return _asyncState; }
            }

            public WaitHandle AsyncWaitHandle
            {
                get { return _waitHandle; }
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

            public void Dispose()
            {
                _waitHandle.Close();
            }

            public void SetComplete(bool errorOccured)
            {
                lock (_lock)
                {
                    if (!_isCompleted)
                    {
                        _isCompleted = true;
                        _isCompletedSynchronously = true;
                        if (errorOccured == false && _callback != null)
                        {
                            _callback.Invoke(this);
                        }
                    }
                }

                if (!_waitHandle.Set())
                {
                    throw new KsiException("WaitHandle completion failed");
                }
            }
        }
    }
}