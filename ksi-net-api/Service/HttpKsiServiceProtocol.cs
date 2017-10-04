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
        private readonly int _requestTimeOut = 10000;
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
        ///     Begin extending request.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service async result</returns>
        public IAsyncResult BeginExtend(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginExtenderRequest(data, requestId, callback, asyncState);
        }

        /// <summary>
        ///     Begin extender configuration request.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service async result</returns>
        public IAsyncResult BeginGetExtenderConfig(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginExtenderRequest(data, requestId, callback, asyncState);
        }

        private IAsyncResult BeginExtenderRequest(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            HttpWebRequest request = null;
            Exception webRequestException = null;

            try
            {
                request = WebRequest.Create(_extendingUrl) as HttpWebRequest;

                if (request == null)
                {
                    throw new KsiException("Invalid http web request: null.");
                }

                InitProxySettings(request);
                request.KeepAlive = false;
                request.ServicePoint.Expect100Continue = false;
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

            HttpKsiServiceAsyncResult httpAsyncResult = new HttpKsiServiceAsyncResult(request, data, requestId, callback, asyncState);

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
        ///     End extend.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        ///     End extender configuration request.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndGetExtenderConfig(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        ///     Begin get publications file.
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            HttpWebRequest request = null;
            Exception webRequestException = null;

            try
            {
                request = WebRequest.Create(_publicationsFileUrl) as HttpWebRequest;

                if (request == null)
                {
                    throw new KsiException("Invalid http web request: null.");
                }

                InitProxySettings(request);
                request.KeepAlive = false;
                request.ServicePoint.Expect100Continue = false;
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

            HttpKsiServiceAsyncResult httpAsyncResult = new HttpKsiServiceAsyncResult(request, null, Utils.Util.GetRandomUnsignedLong(), callback, asyncState);

            Logger.Debug("Begin get publications file http request (request id: {0})", httpAsyncResult.RequestId);

            request.BeginGetResponse(GetPublicationResponseCallback, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.BeginWaitHandle, EndBeginCallback, httpAsyncResult, _requestTimeOut, true);

            return httpAsyncResult;
        }

        private void GetPublicationResponseCallback(IAsyncResult ar)
        {
            HttpKsiServiceAsyncResult asyncResult = (HttpKsiServiceAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                using (WebResponse response = asyncResult.Request.EndGetResponse(ar))
                {
                    HandleWebResponse(response, asyncResult);
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
        /// <param name="ar">HTTP KSI service async result</param>
        /// <returns>publications file bytes</returns>
        public byte[] EndGetPublicationsFile(IAsyncResult ar)
        {
            HttpKsiServiceAsyncResult asyncResult = ar as HttpKsiServiceAsyncResult;
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

            Logger.Debug("Service protocol returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

            return asyncResult.ResultStream.ToArray();
        }

        /// <summary>
        ///     Begin signing request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId"></param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service async result</returns>
        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginAggregatorRequest(data, requestId, callback, asyncState);
        }

        /// <summary>
        ///     Begin aggregator configuration request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service async result</returns>
        public IAsyncResult BeginGetAggregatorConfig(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginAggregatorRequest(data, requestId, callback, asyncState);
        }

        private IAsyncResult BeginAggregatorRequest(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            HttpWebRequest request = null;
            Exception webRequestException = null;

            try
            {
                request = WebRequest.Create(_signingUrl) as HttpWebRequest;

                if (request == null)
                {
                    throw new KsiException("Invalid http web request: null.");
                }

                InitProxySettings(request);
                request.KeepAlive = false;
                request.ServicePoint.Expect100Continue = false;
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

            HttpKsiServiceAsyncResult httpAsyncResult = new HttpKsiServiceAsyncResult(request, data, requestId, callback, asyncState);

            Logger.Debug("Begin sign http request (request id: {0}).", httpAsyncResult.RequestId);

            request.BeginGetRequestStream(GetRequestStreamCallback, httpAsyncResult);
            ThreadPool.RegisterWaitForSingleObject(httpAsyncResult.BeginWaitHandle, EndBeginCallback, httpAsyncResult, _requestTimeOut, true);
            return httpAsyncResult;
        }

        /// <summary>
        ///     End signing request.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndSign(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        ///     End aggregator configuration request.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndGetAggregatorConfig(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        private void GetRequestStreamCallback(IAsyncResult ar)
        {
            HttpKsiServiceAsyncResult asyncResult = (HttpKsiServiceAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

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
            HttpKsiServiceAsyncResult asyncResult = (HttpKsiServiceAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                using (WebResponse response = asyncResult.Request.EndGetResponse(ar))
                {
                    HandleWebResponse(response, asyncResult);
                    asyncResult.BeginWaitHandle.Set();
                }
            }
            catch (WebException e)
            {
                HttpWebResponse webResponse = e.Response as HttpWebResponse;

                if (webResponse != null && webResponse.StatusCode == HttpStatusCode.BadRequest)
                {
                    asyncResult.ResultStream = new MemoryStream();
                    HandleWebResponse(e.Response, asyncResult);
                    asyncResult.BeginWaitHandle.Set();
                }
                else
                {
                    SetError(asyncResult, e, "Get http response failed.");
                }
            }
        }

        private void HandleWebResponse(WebResponse response, HttpKsiServiceAsyncResult asyncResult)
        {
            byte[] buffer = new byte[_bufferSize];

            try
            {
                using (Stream s = response.GetResponseStream())
                {
                    int bytesLength;
                    while (s != null && (bytesLength = s.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        asyncResult.ResultStream.Write(buffer, 0, bytesLength);
                    }
                }
                Logger.Debug("Handle http web response successful (request id: {0})", asyncResult.RequestId);
            }
            catch (Exception ex)
            {
                SetError(asyncResult, ex, "Handling web response failed.");
            }
        }

        private static void EndBeginCallback(object state, bool timedOut)
        {
            HttpKsiServiceAsyncResult httpAsyncResult = (HttpKsiServiceAsyncResult)state;

            if (timedOut)
            {
                Logger.Debug("Request timed out (request id: {0})", httpAsyncResult.RequestId);
                httpAsyncResult.Error = new KsiServiceProtocolException("Request timed out.");
            }

            httpAsyncResult.SetComplete();
        }

        /// <summary>
        ///     End get result from web request.
        /// </summary>
        /// <param name="ar">HTTP KSI service async result</param>
        /// <returns>result bytes</returns>
        private byte[] EndGetResult(IAsyncResult ar)
        {
            HttpKsiServiceAsyncResult asyncResult = ar as HttpKsiServiceAsyncResult;
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

            Logger.Debug("Service protocol returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

            return asyncResult.ResultStream.ToArray();
        }

        private static void SetError(HttpKsiServiceAsyncResult asyncResult, Exception e, string errorMessage)
        {
            string message = errorMessage + string.Format(" (request id: {0}).", asyncResult.RequestId);
            Logger.Warn(message + " " + e);
            asyncResult.Error = new KsiServiceProtocolException(message, e);
            asyncResult.BeginWaitHandle.Set();
        }

        /// <summary>
        ///     HTTP KSI service async result.
        /// </summary>
        private class HttpKsiServiceAsyncResult : KsiServiceAsyncResult
        {
            public HttpKsiServiceAsyncResult(HttpWebRequest request, byte[] postData, ulong requestId, AsyncCallback callback, object asyncState)
                : base(postData, requestId, callback, asyncState)
            {
                if (request == null)
                {
                    throw new ArgumentNullException(nameof(request));
                }

                Request = request;
                BeginWaitHandle = new ManualResetEvent(false);
            }

            public HttpWebRequest Request { get; }

            public ManualResetEvent BeginWaitHandle { get; }
        }
    }
}