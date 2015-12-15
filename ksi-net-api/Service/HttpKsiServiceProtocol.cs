using System;
using System.IO;
using System.Net;
using System.Threading;
using Guardtime.KSI.Exceptions;
using NLog;

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
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

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
                throw new KsiServiceProtocolException("Request timeout should be in milliseconds, but was (" + requestTimeout + ").");
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
                throw new KsiServiceProtocolException("Buffer size should be in positive integer, but was (" + bufferSize + ").");
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

            HttpWebRequest request = null;
            Exception webRequestException = null;

            try
            {
                request = WebRequest.Create(_extendingUrl) as HttpWebRequest;
            }
            catch (Exception e)
            {
                webRequestException = e;
            }

            if (request == null || webRequestException != null)
            {
                string message = "Begin extend request failed. Invalid extending service HTTP URL(\"" + _extendingUrl + "\").";
                Logger.Warn(message + " " + webRequestException);
                throw new KsiServiceProtocolException(message, webRequestException);
            }

            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, callback, asyncState);

            Logger.Debug("Begin extend request (request guid: {0}).", httpAsyncResult.RequestId);

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
            HttpWebRequest request = null;
            Exception webRequestException = null;

            try
            {
                request = WebRequest.Create(_publicationsFileUrl) as HttpWebRequest;
            }
            catch (Exception e)
            {
                webRequestException = e;
            }

            if (request == null || webRequestException != null)
            {
                string message = "Begin get publications file request failed. Invalid publications file HTTP URL(\"" + _publicationsFileUrl + "\").";
                Logger.Warn(message + " " + webRequestException);
                throw new KsiServiceProtocolException(message, webRequestException);
            }

            request.Method = WebRequestMethods.Http.Get;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, null, callback, asyncState);

            Logger.Debug("Begin get publications file request (request guid: {0})", httpAsyncResult.RequestId);

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
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = asyncResult as HttpKsiServiceProtocolAsyncResult;
            if (httpAsyncResult == null)
            {
                throw new KsiServiceProtocolException("Invalid IAsyncResult.");
            }

            if (!httpAsyncResult.IsCompleted)
            {
                httpAsyncResult.AsyncWaitHandle.WaitOne();
            }

            if (httpAsyncResult.HasError)
            {
                string message = string.Format("End get publications file request failed (request guid: {0}).", httpAsyncResult.RequestId);
                Logger.Warn(message + " " + httpAsyncResult.Error);
                throw new KsiServiceProtocolException(message, httpAsyncResult.Error);
            }

            try
            {
                using (WebResponse response = httpAsyncResult.Request.EndGetResponse(httpAsyncResult.ResponseAsyncResult))
                {
                    return HandleWebResponse(response, httpAsyncResult.RequestId);
                }
            }
            catch (WebException e)
            {
                string message = string.Format("End get publications file request failed. Get response failed (request guid: {0}).", httpAsyncResult.RequestId);
                Logger.Warn(message + " " + e);
                throw new KsiServiceProtocolException(message, e);
            }
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

            HttpWebRequest request = null;
            Exception webRequestException = null;

            try
            {
                request = WebRequest.Create(_signingUrl) as HttpWebRequest;
            }
            catch (Exception e)
            {
                webRequestException = e;
            }

            if (request == null || webRequestException != null)
            {
                string message = "Begin sign request failed. Invalid signing service HTTP URL(\"" + _signingUrl + "\").";
                Logger.Warn(message + " " + webRequestException);
                throw new KsiServiceProtocolException(message, webRequestException);
            }

            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, callback, asyncState);

            Logger.Debug("Begin sign request (request guid: {0}).", httpAsyncResult.RequestId);

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
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = (HttpKsiServiceProtocolAsyncResult)state;

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
                using (Stream stream = httpAsyncResult.Request.EndGetRequestStream(httpAsyncResult.StreamAsyncResult))
                {
                    stream.Write(data, 0, data.Length);
                }

                httpAsyncResult.ResponseAsyncResult = httpAsyncResult.Request.BeginGetResponse(null, httpAsyncResult);
                ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.ResponseAsyncResult.AsyncWaitHandle,
                    EndAsyncGetResponseCallback, httpAsyncResult, timeRemaining, true);
            }
            catch (Exception e)
            {
                httpAsyncResult.Error = new KsiServiceProtocolException("Request failed with following error \"" + e + "\".", e);
                httpAsyncResult.SetComplete(true);
            }
        }

        private static void EndAsyncGetResponseCallback(object state, bool timedOut)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = (HttpKsiServiceProtocolAsyncResult)state;

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

            if (httpAsyncResult.HasError)
            {
                string message = string.Format("End http request failed (request guid: {0}).", httpAsyncResult.RequestId);
                Logger.Warn(message + " " + httpAsyncResult.Error);
                throw new KsiServiceProtocolException(message, httpAsyncResult.Error);
            }

            try
            {
                using (WebResponse response = httpAsyncResult.Request.EndGetResponse(httpAsyncResult.ResponseAsyncResult))
                {
                    return HandleWebResponse(response, httpAsyncResult.RequestId);
                }
            }
            catch (WebException e)
            {
                if (e.Response != null)
                {
                    return HandleWebResponse(e.Response, httpAsyncResult.RequestId);
                }

                string message = string.Format("End http request failed. Get response failed (request guid: {0}).", httpAsyncResult.RequestId);
                Logger.Warn(message + " " + e);
                throw new KsiServiceProtocolException(message, e);
            }
        }

        private byte[] HandleWebResponse(WebResponse response, Guid requestId)
        {
            byte[] buffer = new byte[_bufferSize];

            using (Stream s = response.GetResponseStream())
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    int bytesLength;
                    while (s != null && (bytesLength = s.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        memoryStream.Write(buffer, 0, bytesLength);
                    }

                    Logger.Debug("End http request success (request guid: {0})", requestId);

                    return memoryStream.ToArray();
                }
            }
        }

        /// <summary>
        ///     HTTP KSI service protocol async result.
        /// </summary>
        private class HttpKsiServiceProtocolAsyncResult : IAsyncResult, IDisposable
        {
            private readonly AsyncCallback _callback;
            private readonly object _lock;

            private readonly DateTime _startTime = DateTime.Now;
            private readonly ManualResetEvent _waitHandle;
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

                Request = request;
                PostData = postData;
                _callback = callback;
                AsyncState = asyncState;

                _isCompleted = false;
                _isCompletedSynchronously = false;

                _lock = new object();
                _waitHandle = new ManualResetEvent(false);
                RequestId = Guid.NewGuid();
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

            public Guid RequestId { get; }

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

            public HttpWebRequest Request { get; }

            public byte[] PostData { get; }

            public int TimeElapsed => (int)(DateTime.Now - _startTime).TotalMilliseconds;

            public bool HasError => Error != null;

            public Exception Error { get; set; }

            public object AsyncState { get; }

            public WaitHandle AsyncWaitHandle => _waitHandle;

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
                        if (errorOccured == false)
                        {
                            _callback?.Invoke(this);
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