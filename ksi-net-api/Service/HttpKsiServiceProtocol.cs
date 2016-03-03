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
        private readonly int _bufferSize = 8192;
        private readonly string _extendingUrl;
        private readonly string _publicationsFileUrl;
        private readonly int _requestTimeOut = 2000;
        private readonly string _signingUrl;
        private readonly string _proxyUrl;
        private readonly NetworkCredential _proxyCredential;
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
        ///     Create HTTP KSI service protocol with given url-s
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="extendingUrl">extending url</param>
        /// <param name="publicationsFileUrl">publications file url</param>
        /// <param name="proxyUrl">proxy url</param>
        /// <param name="proxyCredential">credentials for proxy</param>
        public HttpKsiServiceProtocol(string signingUrl, string extendingUrl, string publicationsFileUrl, string proxyUrl, NetworkCredential proxyCredential)
            : this(signingUrl, extendingUrl, publicationsFileUrl)
        {
            _proxyUrl = proxyUrl;
            _proxyCredential = proxyCredential;
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
        ///     Create HTTP KSI service protocol with given url-s and request timeout
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="extendingUrl">extending url</param>
        /// <param name="publicationsFileUrl">publications file url</param>
        /// <param name="requestTimeout">request timeout</param>
        /// <param name="proxyUrl">proxy url</param>
        /// <param name="proxyCredential">credentials for proxy</param>
        public HttpKsiServiceProtocol(string signingUrl, string extendingUrl, string publicationsFileUrl,
                                      int requestTimeout, string proxyUrl, NetworkCredential proxyCredential) : this(signingUrl, extendingUrl, publicationsFileUrl, requestTimeout)
        {
            _proxyUrl = proxyUrl;
            _proxyCredential = proxyCredential;
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
        ///     Create HTTP KSI service protocol with given url-s, request timeout and buffer size
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="extendingUrl">extending url</param>
        /// <param name="publicationsFileUrl">publications file url</param>
        /// <param name="requestTimeout">request timeout</param>
        /// <param name="bufferSize">buffer size</param>
        /// <param name="proxyUrl">proxy url</param>
        /// <param name="proxyCredential">credentials for proxy</param>
        public HttpKsiServiceProtocol(string signingUrl, string extendingUrl, string publicationsFileUrl,
                                      int requestTimeout, int bufferSize, string proxyUrl, NetworkCredential proxyCredential)
            : this(signingUrl, extendingUrl, publicationsFileUrl, requestTimeout, bufferSize)
        {
            _proxyUrl = proxyUrl;
            _proxyCredential = proxyCredential;
        }

        /// <summary>
        ///     Begin extend signature.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginExtend(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
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
                InitProxySettings(request);
            }
            catch (Exception e)
            {
                webRequestException = e;
            }

            if (request == null || webRequestException != null)
            {
                string message = "Begin extend http request failed. Invalid extending service HTTP URL(\"" + _extendingUrl + "\").";
                Logger.Warn(message + " " + webRequestException);
                throw new KsiServiceProtocolException(message, webRequestException);
            }

            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, requestId, callback, asyncState);

            Logger.Debug("Begin extend http request (request id: {0}).", httpAsyncResult.RequestId);

            request.BeginGetRequestStream(GetRequestStreamCallback, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.BeginWaitHandle, EndBeginCallback, httpAsyncResult, _requestTimeOut, true);
            return httpAsyncResult;
        }

        private void InitProxySettings(HttpWebRequest request)
        {
            if (string.IsNullOrEmpty(_proxyUrl))
            {
                return;
            }

            WebProxy proxy = new WebProxy();
            Uri uri = new Uri(_proxyUrl);
            proxy.Address = uri;
            if (_proxyCredential != null)
            {
                proxy.Credentials = _proxyCredential;
            }
            request.Proxy = proxy;
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
                InitProxySettings(request);
            }
            catch (Exception e)
            {
                webRequestException = e;
            }

            if (request == null || webRequestException != null)
            {
                string message = "Begin get publications file http request failed. Invalid publications file HTTP URL(\"" + _publicationsFileUrl + "\").";
                Logger.Warn(message + " " + webRequestException);
                throw new KsiServiceProtocolException(message, webRequestException);
            }

            request.Method = WebRequestMethods.Http.Get;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, null, Utils.Util.GetRandomUnsignedLong(), callback, asyncState);

            Logger.Debug("Begin get publications file http request (request id: {0})", httpAsyncResult.RequestId);

            request.BeginGetResponse(GetPublicationResponseCallback, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.BeginWaitHandle, EndBeginCallback, httpAsyncResult, _requestTimeOut, true);

            return httpAsyncResult;
        }

        private void GetPublicationResponseCallback(IAsyncResult ar)
        {
            HttpKsiServiceProtocolAsyncResult asyncResult = (HttpKsiServiceProtocolAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                using (WebResponse response = asyncResult.Request.EndGetResponse(ar))
                {
                    HandleWebResponse(response, asyncResult.ResultStream, asyncResult.RequestId);
                    asyncResult.BeginWaitHandle.Set();
                }
            }
            catch (WebException e)
            {
                SetError(asyncResult, e, "Get publication http response failed.");
            }
        }

        /// <summary>
        ///     End get publications file.
        /// </summary>
        /// <param name="ar">HTTP KSI service protocol async result</param>
        /// <returns>publications file bytes</returns>
        public byte[] EndGetPublicationsFile(IAsyncResult ar)
        {
            HttpKsiServiceProtocolAsyncResult asyncResult = ar as HttpKsiServiceProtocolAsyncResult;
            if (asyncResult == null)
            {
                throw new KsiServiceProtocolException("Invalid IAsyncResult.");
            }

            if (!asyncResult.IsCompleted)
            {
                asyncResult.AsyncWaitHandle.WaitOne();
            }

            if (asyncResult.HasError)
            {
                throw asyncResult.Error;
            }

            Logger.Debug("Returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

            return asyncResult.ResultStream.ToArray();
        }

        /// <summary>
        ///     Begin create signature.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId"></param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
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
                InitProxySettings(request);
            }
            catch (Exception e)
            {
                webRequestException = e;
            }

            if (request == null || webRequestException != null)
            {
                string message = "Begin sign http request failed. Invalid signing service HTTP URL(\"" + _signingUrl + "\").";
                Logger.Warn(message + " " + webRequestException);
                throw new KsiServiceProtocolException(message, webRequestException);
            }

            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, requestId, callback, asyncState);

            Logger.Debug("Begin sign http brequest (request id: {0}).", httpAsyncResult.RequestId);

            request.BeginGetRequestStream(GetRequestStreamCallback, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.BeginWaitHandle, EndBeginCallback, httpAsyncResult, _requestTimeOut, true);
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

        private void GetRequestStreamCallback(IAsyncResult ar)
        {
            HttpKsiServiceProtocolAsyncResult asyncResult = (HttpKsiServiceProtocolAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

            asyncResult.Request.Timeout = _requestTimeOut - asyncResult.TimeElapsed;
            byte[] data = asyncResult.PostData;
            try
            {
                using (Stream stream = asyncResult.Request.EndGetRequestStream(ar))
                {
                    stream.Write(data, 0, data.Length);
                }

                if (asyncResult.IsCompleted)
                {
                    return;
                }

                asyncResult.Request.BeginGetResponse(GetResponseCallback, asyncResult);
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Request failed.");
            }
        }

        private void GetResponseCallback(IAsyncResult ar)
        {
            HttpKsiServiceProtocolAsyncResult asyncResult = (HttpKsiServiceProtocolAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                using (WebResponse response = asyncResult.Request.EndGetResponse(ar))
                {
                    HandleWebResponse(response, asyncResult.ResultStream, asyncResult.RequestId);
                    asyncResult.BeginWaitHandle.Set();
                }
            }
            catch (WebException e)
            {
                if (e.Response != null)
                {
                    asyncResult.ResultStream = new MemoryStream();
                    HandleWebResponse(e.Response, asyncResult.ResultStream, asyncResult.RequestId);
                    asyncResult.BeginWaitHandle.Set();
                    return;
                }

                SetError(asyncResult, e, "Get http response failed.");
            }
        }

        private void HandleWebResponse(WebResponse response, MemoryStream memoryStream, ulong requestId)
        {
            byte[] buffer = new byte[_bufferSize];

            using (Stream s = response.GetResponseStream())
            {
                int bytesLength;
                while (s != null && (bytesLength = s.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memoryStream.Write(buffer, 0, bytesLength);
                }

                Logger.Debug("End http request success (request id: {0})", requestId);
            }
        }

        private static void EndBeginCallback(object state, bool timedOut)
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
        /// <param name="ar">HTTP KSI service protocol async result</param>
        /// <returns>result bytes</returns>
        private byte[] EndGetResult(IAsyncResult ar)
        {
            HttpKsiServiceProtocolAsyncResult asyncResult = ar as HttpKsiServiceProtocolAsyncResult;
            if (asyncResult == null)
            {
                throw new KsiServiceProtocolException("Invalid IAsyncResult.");
            }

            if (!asyncResult.IsCompleted)
            {
                asyncResult.AsyncWaitHandle.WaitOne();
            }

            if (asyncResult.HasError)
            {
                throw asyncResult.Error;
            }

            Logger.Debug("Returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

            return asyncResult.ResultStream.ToArray();
        }

        private static void SetError(HttpKsiServiceProtocolAsyncResult asyncResult, Exception e, string errorMessage)
        {
            string message = errorMessage + string.Format(" (request id: {0}).", asyncResult.RequestId);
            Logger.Warn(message + " " + e);
            asyncResult.Error = new KsiServiceProtocolException(message, e);
            asyncResult.BeginWaitHandle.Set();
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

            public HttpKsiServiceProtocolAsyncResult(HttpWebRequest request, byte[] postData, ulong requestId, AsyncCallback callback,
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

                _lock = new object();
                _waitHandle = new ManualResetEvent(false);
                BeginWaitHandle = new ManualResetEvent(false);
                RequestId = requestId;
                ResultStream = new MemoryStream();
            }

            public ulong RequestId { get; }

            public MemoryStream ResultStream { get; set; }

            public HttpWebRequest Request { get; }

            public byte[] PostData { get; }

            public int TimeElapsed => (int)(DateTime.Now - _startTime).TotalMilliseconds;

            public bool HasError => Error != null;

            public Exception Error { get; set; }

            public object AsyncState { get; }

            public WaitHandle AsyncWaitHandle => _waitHandle;

            public ManualResetEvent BeginWaitHandle { get; }

            public bool CompletedSynchronously => false;

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
                BeginWaitHandle.Close();
                ResultStream?.Dispose();
            }

            public void SetComplete(bool errorOccured)
            {
                lock (_lock)
                {
                    if (!_isCompleted)
                    {
                        _isCompleted = true;

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