﻿using System;
using System.IO;
using System.Net;
using System.Threading;

namespace Guardtime.KSI.Service
{

    // TODO: Make thread safe
    // TODO: Should be possible to set timeout

    // TODO: Better names
    /// <summary>
    /// Http ksi service protocol.
    /// </summary>
    public class HttpKsiServiceProtocol : IKsiSigningServiceProtocol, IKsiExtendingServiceProtocol, IKsiPublicationsFileServiceProtocol
    {
        private readonly int _bufferSize = 8092;

        private readonly string _signingUrl;
        private readonly string _extendingUrl;
        private readonly string _publicationsFileUrl;


        /// <summary>
        /// Create http KSI service protocol with given url-s
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
        /// Create http KSI service protocol with given url-s and buffer size
        /// </summary>
        /// <param name="signingUrl">signing url</param>
        /// <param name="extendingUrl">extending url</param>
        /// <param name="publicationsFileUrl">publications file url</param>
        /// <param name="bufferSize">buffer size</param>
        public HttpKsiServiceProtocol(string signingUrl, string extendingUrl, string publicationsFileUrl, int bufferSize) : this(signingUrl, extendingUrl, publicationsFileUrl)
        {
            _bufferSize = bufferSize;
        }



        /// <summary>
        /// Begin create signature.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginSign(byte[] data, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }
            // TODO: URLs from conf
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(_signingUrl);

            // TODO: Seems to work with expect100
            //request.ServicePoint.Expect100Continue = false;
            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, callback, asyncState);
            request.BeginGetRequestStream(EndAsyncGetRequestStreamCallback, httpAsyncResult);
            return httpAsyncResult;
        }

        /// <summary>
        /// End create signature.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>aggregation response bytes</returns>
        public byte[] EndSign(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        /// Begin extend signature.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="callback">callback when extending signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginExtend(byte[] data, AsyncCallback callback, object asyncState)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            WebRequest request = WebRequest.Create(_extendingUrl);
            request.Method = WebRequestMethods.Http.Post;
            request.ContentType = "application/ksi-request";
            request.ContentLength = data.Length;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, data, callback, asyncState);
            request.BeginGetRequestStream(EndAsyncGetRequestStreamCallback, httpAsyncResult);
            return httpAsyncResult;
        }

        /// <summary>
        /// End extend signature.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>extending response bytes</returns>
        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        /// Begin get publications file.
        /// </summary>
        /// <param name="callback">callback when publications file is downloaded</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>HTTP KSI service protocol async result</returns>
        public IAsyncResult BeginGetPublicationsFile(AsyncCallback callback, object asyncState)
        {
            WebRequest request = WebRequest.Create(_publicationsFileUrl);
            request.Method = WebRequestMethods.Http.Get;

            HttpKsiServiceProtocolAsyncResult httpAsyncResult = new HttpKsiServiceProtocolAsyncResult(request, null, callback, asyncState);
            httpAsyncResult.ResponseAsyncResult = request.BeginGetResponse(EndAsyncGetResponseCallback, httpAsyncResult);
            return httpAsyncResult;
        }

        /// <summary>
        /// End get publications file.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>publications file bytes</returns>
        public byte[] EndGetPublicationsFile(IAsyncResult asyncResult)
        {
            return EndGetResult(asyncResult);
        }

        /// <summary>
        /// End async get request stream callback.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        private void EndAsyncGetRequestStreamCallback(IAsyncResult asyncResult)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = (HttpKsiServiceProtocolAsyncResult)asyncResult.AsyncState;

            byte[] data = httpAsyncResult.PostData;
            Stream stream = httpAsyncResult.Request.EndGetRequestStream(asyncResult);
            stream.Write(data, 0, data.Length);
            stream.Close();

            httpAsyncResult.ResponseAsyncResult = httpAsyncResult.Request.BeginGetResponse(EndAsyncGetResponseCallback, httpAsyncResult);
        }

        /// <summary>
        /// End async get response callback.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        private void EndAsyncGetResponseCallback(IAsyncResult asyncResult)
        {
            HttpKsiServiceProtocolAsyncResult httpAsyncResult = (HttpKsiServiceProtocolAsyncResult)asyncResult.AsyncState;
            httpAsyncResult.SetComplete();
        }

        /// <summary>
        /// End get result from web request.
        /// </summary>
        /// <param name="asyncResult">HTTP KSI service protocol async result</param>
        /// <returns>result bytes</returns>
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
            byte[] buffer = new byte[_bufferSize];
            try
            {
                WebResponse response = httpAsyncResult.Request.EndGetResponse(httpAsyncResult.ResponseAsyncResult);
                if (response == null)
                {
                    // TODO: When response is empty
                    throw new Exception("Problem");
                }

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
                    // TODO: Correct exception
                    throw new Exception("Response message missing", e);
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
        /// HTTP KSI service protocol async result.
        /// </summary>
        private class HttpKsiServiceProtocolAsyncResult : IAsyncResult
        {
            private bool _isCompleted;
            private bool _isCompletedSynchronously;
            private readonly ManualResetEvent _waitHandle;
            private readonly object _asyncState;

            private readonly AsyncCallback _callback;

            private readonly object _lock;

            private IAsyncResult _responseAsyncResult;

            private readonly WebRequest _request;
            private readonly byte[] _postData;

            public HttpKsiServiceProtocolAsyncResult(WebRequest request, byte[] postData, AsyncCallback callback, object asyncState)
            {
                if (request == null)
                {
                    throw new ArgumentNullException("request");
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
                    throw new Exception("WaitHandle completion failed");
                }
            }
        }
    }

    
}
