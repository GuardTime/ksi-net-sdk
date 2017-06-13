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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// TCP KSI service protocol.
    /// All requests and responses go through one socket that is kept opened for future requests.
    /// If a request fails (eg. socket is closed by server) it will be repeated once more with a new freshly connected socket.
    /// </summary>
    public partial class TcpKsiServiceProtocol : IKsiSigningServiceProtocol, IDisposable
    {
        private enum RequestType
        {
            Aggregation,
            AggregatorConfig
        };

        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly uint _requestTimeOut = 10000;
        private readonly uint _bufferSize = 8192;
        readonly byte[] _receiveDataBuffer;
        private readonly IPAddress _ipAddress;
        private readonly ushort _port;
        private Socket _socket;
        private readonly object _syncObject = new object();
        private bool _isDisposed;
        private ManualResetEvent _waitSocketConnectHandle;
        private ManualResetEvent _waitHandle;
        private bool _isReceivingRetry;
        private readonly TcpResponseProcessor _responseProcessor;
        private readonly AsyncResultCollection _asyncResults;

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="ipAddress">Signing service IP address</param>
        /// <param name="port">Signing service port</param>
        public TcpKsiServiceProtocol(IPAddress ipAddress, ushort port)
        {
            if (ipAddress == null)
            {
                throw new ArgumentNullException(nameof(ipAddress));
            }

            _ipAddress = ipAddress;
            _port = port;
            _receiveDataBuffer = new byte[_bufferSize];
            _asyncResults = new AsyncResultCollection();
            _responseProcessor = new TcpResponseProcessor(_asyncResults);
        }

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="ipAddress">Signing service IP address</param>
        /// <param name="port">Signing service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        public TcpKsiServiceProtocol(IPAddress ipAddress, ushort port, uint requestTimeout) : this(ipAddress, port)
        {
            _requestTimeOut = requestTimeout;
        }

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="ipAddress">Signing service IP address</param>
        /// <param name="port">Signing service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">size of buffer to be used when receiving data</param>
        public TcpKsiServiceProtocol(IPAddress ipAddress, ushort port, uint requestTimeout, uint bufferSize) : this(ipAddress, port, requestTimeout)
        {
            if (bufferSize == 0)
            {
                throw new KsiServiceProtocolException("Buffer size should be in positive integer, but was (" + bufferSize + ").");
            }

            _bufferSize = bufferSize;
        }

        /// <summary>
        ///    Begin signing request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service protocol async result</returns>
        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginAggregatorRequest(RequestType.Aggregation, data, requestId, callback, asyncState);
        }

        /// <summary>
        ///       Begin aggregator configuration request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service protocol async result</returns>
        public IAsyncResult BeginGetAggregatorConfig(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            return BeginAggregatorRequest(RequestType.AggregatorConfig, data, 0, callback, asyncState);
        }

        /// <summary>
        ///     End signing request.
        /// </summary>
        /// <param name="ar">TCP KSI service protocol async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndSign(IAsyncResult ar)
        {
            return EndRequest(ar);
        }

        /// <summary>
        ///     End aggregator configuration request.
        /// </summary>
        /// <param name="ar">async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndGetAggregatorConfig(IAsyncResult ar)
        {
            return EndRequest(ar);
        }

        /// <summary>
        /// Dispose TCP KSI service protocol. Close opened connection.
        /// </summary>
        public void Dispose()
        {
            _waitHandle?.WaitOne();
            // make new signing requests, retrying and error throwing to wait
            _waitHandle = new ManualResetEvent(false);

            Logger.Debug("Disposing TCP KSI service protocol.");

            if (_isDisposed)
            {
                throw new KsiServiceProtocolException("TCP KSI service protocol is already disposed.");
            }

            _isDisposed = true;
            CloseSocket();

            _waitHandle.Set();
        }

        private void CloseSocket()
        {
            if (_socket != null)
            {
                Logger.Debug("Closing socket. Handle: " + _socket.Handle);
                if (_socket.Connected)
                {
                    _socket.Shutdown(SocketShutdown.Both);
                    _socket.Disconnect(false);
                }
                _socket.Close();

                _socket = null;
            }

            _waitSocketConnectHandle.Set();
            _waitSocketConnectHandle.Close();
            _waitSocketConnectHandle = null;

            _responseProcessor.Clear();
        }

        private IAsyncResult BeginAggregatorRequest(RequestType requestType, byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            if (_isDisposed)
            {
                throw new KsiServiceProtocolException("TCP KSI service protocol is disposed.");
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            TcpKsiServiceProtocolAsyncResult asyncResult = new TcpKsiServiceProtocolAsyncResult(requestType, data, requestId, callback, asyncState);
            // wait until retrying, disposing or error throwing is in progress
            _waitHandle?.WaitOne();
            _asyncResults.Add(requestId, asyncResult);

            if (_socket == null)
            {
                CreateSocketAndConnect();
            }

            BeginSend(asyncResult);

            ThreadPool.RegisterWaitForSingleObject(asyncResult.AsyncWaitHandle, EndBeginSignCallback, asyncResult, _requestTimeOut, true);
            return asyncResult;
        }

        private void CreateSocketAndConnect()
        {
            lock (_syncObject)
            {
                if (_waitSocketConnectHandle == null)
                {
                    _waitSocketConnectHandle = new ManualResetEvent(false);
                }
                else
                {
                    _waitSocketConnectHandle.WaitOne();
                }
            }

            if (_socket == null)
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                Logger.Debug("New TCP socket created. (Socket handle: {0}).", _socket.Handle);

                Logger.Debug("Begin TCP socket connection. (Socket handle: {0}).", _socket.Handle);
                _socket.BeginConnect(new IPEndPoint(_ipAddress, _port), ConnectCallback, null);
            }
        }

        private void ConnectCallback(IAsyncResult ar)
        {
            try
            {
                // Complete the connection.
                _socket.EndConnect(ar);
                Logger.Debug("Socket connected to {0}.", _socket.RemoteEndPoint.ToString());

                if (!_waitSocketConnectHandle.Set())
                {
                    throw new KsiServiceProtocolException("WaitSocketConnectHandle completion failed.");
                }

                Logger.Debug("Starting receiving.");
                _socket.BeginReceive(_receiveDataBuffer, 0, _receiveDataBuffer.Length, 0, ReceiveCallback, null);
            }
            catch (Exception e)
            {
                SetError(e, "Completing connection failed.");
            }
        }

        private void BeginSend(TcpKsiServiceProtocolAsyncResult asyncResult)
        {
            if (asyncResult == null)
            {
                return;
            }

            try
            {
                _waitSocketConnectHandle.WaitOne();
                Logger.Debug("Starting sending (request id: {0}).", asyncResult.RequestId);

                if (!asyncResult.IsCompleted)
                {
                    if (_socket == null)
                    {
                        // stop sending if socket is closed meanwhile
                        Logger.Debug("Stopping sending. No socket. (request id: {0}).", asyncResult.RequestId);
                    }
                    else
                    {
                        _socket.BeginSend(asyncResult.PostData, 0, asyncResult.PostData.Length, 0, SendCallback, asyncResult);
                    }
                }
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Failed to start sending.");
            }
        }

        private void SendCallback(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)ar.AsyncState;

            if (asyncResult.IsCompleted)
            {
                return;
            }

            try
            {
                int bytesSent = _socket.EndSend(ar);
                Logger.Debug("{0} bytes sent to server (request id: {1}).", bytesSent, asyncResult.RequestId);
            }
            catch (Exception e)
            {
                SetError(asyncResult, e, "Failed to complete sending.");
            }
        }

        private void ReceiveCallback(IAsyncResult ar)
        {
            if (_isDisposed)
            {
                Logger.Debug("Exiting receiving due to disposing TCP KSI service protocol.");
                return;
            }

            int bytesRead;

            try
            {
                // Read data from the remote device.
                bytesRead = _socket.EndReceive(ar);

                if (bytesRead == 0)
                {
                    if (!_isReceivingRetry)
                    {
                        Logger.Debug("Received 0 bytes.");
                        RetryUsingNewSocket();
                    }
                    else
                    {
                        SetError(null, "Receiving data failed. Received 0 bytes on second retry.");
                    }
                    return;
                }
            }
            catch (Exception ex)
            {
                SetError(ex, "Reading received data failed.");
                return;
            }

            _isReceivingRetry = false;

            try
            {
                _responseProcessor.ProcessReceivedData(_receiveDataBuffer, bytesRead);
            }
            catch (Exception ex)
            {
                SetError(ex, "Processing received data failed. Result data: " + _responseProcessor.GetEncodedReceivedData());
                return;
            }

            // Get the rest of the data.
            Logger.Debug("Rerun BeginReceive.");
            try
            {
                _socket.BeginReceive(_receiveDataBuffer, 0, _receiveDataBuffer.Length, 0, ReceiveCallback, null);
            }
            catch (Exception ex)
            {
                if (!_isReceivingRetry)
                {
                    Logger.Debug("Rerun BeginReceive failed. Trying once more using new socket. Exception: " + ex);
                    RetryUsingNewSocket();
                }
                else
                {
                    SetError(ex, "Rerun BeginReceive failed.");
                }
            }
        }

        private void RetryUsingNewSocket()
        {
            _waitHandle?.WaitOne();
            // make new signing requests, error throwing and disposing to wait
            _waitHandle = new ManualResetEvent(false);

            try
            {
                CloseSocket();

                if (_asyncResults.Count() == 0)
                {
                    Logger.Debug("No pending signing requests.");
                }
                else
                {
                    _isReceivingRetry = true;
                    CreateSocketAndConnect();

                    Logger.Debug("Rerun all signing requests.");

                    foreach (ulong key in _asyncResults.GetKeys())
                    {
                        BeginSend(_asyncResults.GetValue(key));
                    }
                }
            }
            catch (Exception ex)
            {
                SetError(ex, "Retrying with a new socket failed.");
            }
            finally
            {
                _waitHandle.Set();
            }
        }

        private void EndBeginSignCallback(object state, bool timedOut)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = (TcpKsiServiceProtocolAsyncResult)state;
            _asyncResults.Remove(asyncResult);

            if (timedOut)
            {
                asyncResult.Error = new KsiServiceProtocolException("Sign timed out.");
            }

            asyncResult.SetComplete(timedOut);
        }

        private byte[] EndRequest(IAsyncResult ar)
        {
            TcpKsiServiceProtocolAsyncResult asyncResult = ar as TcpKsiServiceProtocolAsyncResult;

            if (asyncResult == null)
            {
                throw new KsiServiceProtocolException("Invalid IAsyncResult.");
            }

            try
            {
                if (_isDisposed)
                {
                    throw new KsiServiceProtocolException("TCP KSI service protocol is disposed.");
                }

                if (asyncResult.IsDisposed)
                {
                    throw new KsiServiceProtocolException("Provided async result is already disposed. Possibly using the same async result twice when ending your request.");
                }

                if (!asyncResult.IsCompleted)
                {
                    asyncResult.AsyncWaitHandle.WaitOne();
                }

                if (asyncResult.HasError)
                {
                    Logger.Warn("{0} (request id: {1}){2}{3}", asyncResult.Error.Message, asyncResult.RequestId, Environment.NewLine, asyncResult.Error);
                    throw asyncResult.Error;
                }

                Logger.Debug("Service protocol returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

                return asyncResult.ResultStream.ToArray();
            }
            finally
            {
                asyncResult.Dispose();
            }
        }

        private void SetError(Exception e, string errorMessage)
        {
            _waitHandle?.WaitOne();
            // make new signing requests, disposing and retrying to wait
            _waitHandle = new ManualResetEvent(false);

            try
            {
                Logger.Debug(errorMessage + " Closing socket due to error.");
                CloseSocket();

                // no specific asyncResult, notify all pending requests about the error
                foreach (ulong key in _asyncResults.GetKeys())
                {
                    TcpKsiServiceProtocolAsyncResult asyncResult = _asyncResults.GetValue(key);
                    asyncResult.Error = new KsiServiceProtocolException(errorMessage, e);
                    asyncResult.SetComplete(true);
                }

                Logger.Debug("Clearing asyncResults.");
                _asyncResults.Clear();
            }
            finally
            {
                _waitHandle.Set();
            }
        }

        private void SetError(TcpKsiServiceProtocolAsyncResult asyncResult, Exception e, string errorMessage)
        {
            asyncResult.Error = new KsiServiceProtocolException(errorMessage, e);
            asyncResult.SetComplete(true);
            _asyncResults.Remove(asyncResult);
        }

        /// <summary>
        ///     TCP KSI service protocol async result.
        /// </summary>
        private class TcpKsiServiceProtocolAsyncResult : IAsyncResult, IDisposable
        {
            private readonly AsyncCallback _callback;
            private readonly object _lock;
            private readonly ManualResetEvent _waitHandle;
            private bool _isCompleted;
            private bool _isDisposed;

            public TcpKsiServiceProtocolAsyncResult(RequestType requestType, byte[] postData, ulong requestId, AsyncCallback callback, object asyncState)
            {
                PostData = postData;
                _callback = callback;
                AsyncState = asyncState;

                _isCompleted = false;

                _lock = new object();
                _waitHandle = new ManualResetEvent(false);

                RequestType = requestType;
                RequestId = requestId;
            }

            public RequestType RequestType { get; }
            public ulong RequestId { get; }

            public byte[] PostData { get; }

            public MemoryStream ResultStream { get; set; }

            public bool HasError => Error != null;

            public KsiServiceProtocolException Error { get; set; }

            public object AsyncState { get; }

            public WaitHandle AsyncWaitHandle => _waitHandle;

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

            public bool IsDisposed => _isDisposed;

            public void Dispose()
            {
                _waitHandle.Close();
                _isDisposed = true;
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
                    throw new KsiServiceProtocolException("WaitHandle completion failed");
                }
            }
        }

        /// <summary>
        /// Syncronized collection containing TcpKsiServiceProtocol asyncResults.
        /// </summary>
        private class AsyncResultCollection
        {
            readonly Dictionary<ulong, TcpKsiServiceProtocolAsyncResult> _list = new Dictionary<ulong, TcpKsiServiceProtocolAsyncResult>();
            private readonly object _syncObj = new object();

            public void Add(ulong key, TcpKsiServiceProtocolAsyncResult asyncResult)
            {
                lock (_syncObj)
                {
                    _list.Add(key, asyncResult);
                }
            }

            public void Remove(TcpKsiServiceProtocolAsyncResult asyncResult)
            {
                lock (_syncObj)
                {
                    if (_list.ContainsKey(asyncResult.RequestId))
                    {
                        _list.Remove(asyncResult.RequestId);
                    }
                }
            }

            public ulong[] GetKeys()
            {
                lock (_syncObj)
                {
                    ulong[] keys = new ulong[_list.Keys.Count];
                    _list.Keys.CopyTo(keys, 0);
                    return keys;
                }
            }

            public int Count()
            {
                lock (_syncObj)
                {
                    return _list.Count;
                }
            }

            public TcpKsiServiceProtocolAsyncResult GetValue(ulong key)
            {
                lock (_syncObj)
                {
                    return _list.ContainsKey(key) ? _list[key] : null;
                }
            }

            public void Clear()
            {
                lock (_syncObj)
                {
                    _list.Clear();
                }
            }
        }
    }
}