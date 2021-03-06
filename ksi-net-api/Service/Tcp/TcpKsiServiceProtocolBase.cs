﻿/*
 * Copyright 2013-2018 Guardtime, Inc.
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
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Guardtime.KSI.Exceptions;
using NLog;

namespace Guardtime.KSI.Service.Tcp
{
    /// <summary>
    /// Manages TCP requests to one server.
    /// All requests and responses go through one socket that is kept opened for future requests.
    /// If a request fails (eg. socket is closed by server) it will be repeated once more with a new freshly connected socket.
    /// </summary>
    public class TcpKsiServiceProtocolBase : IDisposable
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private readonly int _requestTimeOut = 10000;
        private readonly uint _bufferSize = 8192;
        readonly byte[] _receivedDataBuffer;
        private readonly IPAddress _ipAddress;
        private readonly ushort _port;
        private Socket _socket;
        private readonly object _syncObject = new object();
        private bool _isDisposed;
        private readonly ManualResetEvent _waitSocketConnectHandle;
        private bool _isReceivingRetry;
        private readonly TcpResponseProcessor _responseProcessor;
        private readonly TcpAsyncResultCollection _asyncResults;

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="ipAddress">Service IP address</param>
        /// <param name="port">Service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">size of buffer to be used when receiving data</param>
        public TcpKsiServiceProtocolBase(IPAddress ipAddress, ushort port, uint? requestTimeout = null, uint? bufferSize = null)
        {
            if (ipAddress == null)
            {
                throw new ArgumentNullException(nameof(ipAddress));
            }

            _ipAddress = ipAddress;
            _port = port;

            if (requestTimeout.HasValue)
            {
                _requestTimeOut = (int)requestTimeout.Value;
            }

            if (bufferSize.HasValue)
            {
                if (bufferSize == 0)
                {
                    throw new KsiServiceProtocolException("Buffer size should be a positive integer, but was (" + bufferSize + ").");
                }

                _bufferSize = bufferSize.Value;
            }

            _receivedDataBuffer = new byte[_bufferSize];
            _asyncResults = new TcpAsyncResultCollection();
            _responseProcessor = new TcpResponseProcessor(_asyncResults);
            _waitSocketConnectHandle = new ManualResetEvent(false);
        }

        /// <summary>
        /// Server IP and port.
        /// </summary>
        protected string ServiceAddress => _ipAddress + ":" + _port;

        /// <summary>
        /// Dispose TCP KSI service protocol. Close opened connection.
        /// </summary>
        public void Dispose()
        {
            Logger.Debug("Disposing TCP KSI service protocol.");

            if (_isDisposed)
            {
                throw new KsiServiceProtocolException("TCP KSI service protocol is already disposed.");
            }

            // Wait until making a new request, retrying or error throwing is in progress
            lock (_syncObject)
            {
                _isDisposed = true;
                CloseSocket();
            }
        }

        /// <summary>
        /// Begin TCP request
        /// </summary>
        /// <param name="requestType"></param>
        /// <param name="data">request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when request is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns></returns>
        protected IAsyncResult BeginRequest(KsiServiceRequestType requestType, byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            if (_isDisposed)
            {
                throw new KsiServiceProtocolException("TCP KSI service protocol is disposed.");
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            TcpKsiServiceAsyncResult asyncResult = new TcpKsiServiceAsyncResult(requestType, data, requestId, callback, asyncState);

            Logger.Debug("Begin TCP request (request id: {0}).", asyncResult.RequestId);

            // Wait until retrying, disposing or error throwing is in progress
            lock (_syncObject)
            {
                _asyncResults.Add(requestId, asyncResult);
            }

            if (_socket == null)
            {
                CreateSocketAndConnect();
            }

            // Before starting sending request check that other request (possibly failed) haven't finished and disposed the async result.
            if (!asyncResult.IsDisposed)
            {
                ThreadPool.RegisterWaitForSingleObject(asyncResult.AsyncWaitHandle, EndBeginRequestCallback, asyncResult, _requestTimeOut, true);

                BeginSend(asyncResult);
            }

            return asyncResult;
        }

        /// <summary>
        /// End TCP request
        /// </summary>
        /// <param name="ar">TCP KSI service async result</param>
        /// <returns></returns>
        protected byte[] EndRequest(IAsyncResult ar)
        {
            TcpKsiServiceAsyncResult asyncResult = ar as TcpKsiServiceAsyncResult;

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
                    throw new KsiServiceProtocolException("Provided async result is already disposed. Possibly using the same async result twice when ending request.");
                }

                if (!asyncResult.IsCompleted)
                {
                    if (!asyncResult.AsyncWaitHandle.WaitOne(_requestTimeOut))
                    {
                        Logger.Debug("Request timed out. Waiting asyncResult.AsyncWaitHandle in EndRequest timed out.");
                        throw new KsiServiceProtocolException("Request timed out.");
                    }
                }

                if (asyncResult.HasError)
                {
                    Logger.Warn("{0} (request id: {1}){2}{3}", asyncResult.Error.Message, asyncResult.RequestId, Environment.NewLine, asyncResult.Error);
                    throw asyncResult.Error;
                }

                Logger.Debug("TCP service protocol returning {0} bytes (request id: {1}).", asyncResult.ResultStream.Length, asyncResult.RequestId);

                return asyncResult.ResultStream.ToArray();
            }
            finally
            {
                asyncResult.Dispose();
            }
        }

        private void CloseSocket()
        {
            if (!_waitSocketConnectHandle.Reset())
            {
                throw new KsiServiceProtocolException("_waitSocketConnectHandle reset failed.");
            }

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

            _responseProcessor?.Clear();
        }

        private void CreateSocketAndConnect()
        {
            if (!_waitSocketConnectHandle.Reset())
            {
                throw new KsiServiceProtocolException("_waitSocketConnectHandle reset failed.");
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
            }
            catch (Exception e)
            {
                SetError(e, "Completing connection failed.");
            }
            finally
            {
                if (!_waitSocketConnectHandle.Set())
                {
                    SetError(null, "Set WaitSocketConnectHandle failed.");
                }
            }

            try
            {
                Logger.Debug("Starting receiving.");
                _socket.BeginReceive(_receivedDataBuffer, 0, _receivedDataBuffer.Length, 0, ReceiveCallback, null);
            }
            catch (Exception e)
            {
                SetError(e, "Completing connection failed.");
            }
        }

        private void BeginSend(TcpKsiServiceAsyncResult asyncResult)
        {
            if (asyncResult == null)
            {
                return;
            }

            try
            {
                if (!_waitSocketConnectHandle.WaitOne(_requestTimeOut))
                {
                    Logger.Debug("Request timed out. Waiting _waitSocketConnectHandle in BeginSend timed out.");
                    throw new KsiServiceProtocolException("Request timed out.");
                }

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
            TcpKsiServiceAsyncResult asyncResult = (TcpKsiServiceAsyncResult)ar.AsyncState;

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
                Logger.Debug("Exiting receiving due to disposing of TCP KSI service protocol.");
                return;
            }

            int bytesRead;

            try
            {
                // Read data from the remote device.
                bytesRead = _socket.EndReceive(ar);

                if (bytesRead == 0) // eg. when server closes the connection because of idle time
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
                _responseProcessor.ProcessReceivedData(_receivedDataBuffer, bytesRead);
            }
            catch (Exception ex)
            {
                SetError(ex, "Processing received data failed. " + Environment.NewLine + " Result data: " + _responseProcessor.GetEncodedReceivedData());
                return;
            }

            // Get the rest of the data.
            Logger.Debug("Rerun BeginReceive.");
            try
            {
                _socket.BeginReceive(_receivedDataBuffer, 0, _receivedDataBuffer.Length, 0, ReceiveCallback, null);
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
            // Wait until making a new request, disposing or error throwing is in progress
            lock (_syncObject)
            {
                try
                {
                    CloseSocket();

                    if (_asyncResults.Count() == 0)
                    {
                        Logger.Debug("No pending requests.");
                    }
                    else
                    {
                        _isReceivingRetry = true;
                        CreateSocketAndConnect();

                        Logger.Debug("Rerun all requests.");

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
            }
        }

        private void EndBeginRequestCallback(object state, bool timedOut)
        {
            try
            {
                TcpKsiServiceAsyncResult asyncResult = (TcpKsiServiceAsyncResult)state;
                _asyncResults.Remove(asyncResult);

                if (timedOut)
                {
                    asyncResult.Error = new KsiServiceProtocolException("Request timed out.");
                }

                asyncResult.SetComplete();
            }
            catch (Exception ex)
            {
                Logger.Debug("EndBeginRequestCallback failed.", ex);
                throw;
            }
        }

        private void SetError(Exception e, string errorMessage)
        {
            // Wait until making a new request, retrying or disposing is in progress
            lock (_syncObject)
            {
                try
                {
                    Logger.Debug(errorMessage + Environment.NewLine + e + Environment.NewLine + "Closing socket due to error.");
                    CloseSocket();

                    // no specific asyncResult, notify all pending requests about the error
                    foreach (ulong key in _asyncResults.GetKeys())
                    {
                        TcpKsiServiceAsyncResult asyncResult = _asyncResults.GetValue(key);
                        // If an error already exists then do not overwrite.
                        if (asyncResult.Error != null)
                        {
                            continue;
                        }
                        asyncResult.Error = new KsiServiceProtocolException(errorMessage, e);
                        asyncResult.SetComplete();
                    }

                    Logger.Debug("Clearing asyncResults.");
                    _asyncResults.Clear();
                }
                catch (Exception ex)
                {
                    Logger.Debug("SetError failed.", ex);
                    throw;
                }
            }
        }

        private void SetError(TcpKsiServiceAsyncResult asyncResult, Exception e, string errorMessage)
        {
            try
            {
                // If an error already exists then do not overwrite.
                if (asyncResult.Error != null)
                {
                    return;
                }
                asyncResult.Error = new KsiServiceProtocolException(errorMessage, e);
                asyncResult.SetComplete();
                _asyncResults.Remove(asyncResult);
            }
            catch (Exception ex)
            {
                Logger.Debug("SetError with asyncResult failed.", ex);
                throw;
            }
        }
    }
}