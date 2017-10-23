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
using System.Net;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Service.Tcp;
using NLog;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// TCP KSI service protocol.
    /// Responsible for making TCP requests to aggregator and extender.
    /// </summary>
    public class TcpKsiServiceProtocol : IKsiSigningServiceProtocol, IKsiExtendingServiceProtocol, IDisposable
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();
        private bool _isDisposed;
        private readonly TcpAggregatorRequestManager _aggregatorRequestManager;
        private readonly TcpExtenderRequestManager _extenderRequestManager;

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="signingServiceIpAddress">Signing service IP address</param>
        /// <param name="signingServicePort">Signing service port</param>
        /// <param name="extendingServiceIpAddress">Extending service IP address</param>
        /// <param name="extendingServicePort">Extending service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">size of buffer to be used when receiving data</param>
        public TcpKsiServiceProtocol(IPAddress signingServiceIpAddress, ushort? signingServicePort, IPAddress extendingServiceIpAddress = null, ushort? extendingServicePort = null,
                                     uint? requestTimeout = null, uint? bufferSize = null)
        {
            if (signingServiceIpAddress != null)
            {
                if (!signingServicePort.HasValue)
                {
                    throw new ArgumentException(nameof(signingServicePort) + " cannot be empty if " + nameof(signingServiceIpAddress) + " is given.");
                }

                _aggregatorRequestManager = new TcpAggregatorRequestManager(signingServiceIpAddress, signingServicePort.Value, requestTimeout, bufferSize);
            }

            if (extendingServiceIpAddress != null)
            {
                if (!extendingServicePort.HasValue)
                {
                    throw new ArgumentException(nameof(extendingServicePort) + " cannot be empty if " + nameof(extendingServiceIpAddress) + " is given.");
                }

                _extenderRequestManager = new TcpExtenderRequestManager(extendingServiceIpAddress, extendingServicePort.Value, requestTimeout, bufferSize);
            }
        }

        /// <summary>
        ///     Create TCP KSI service protocol
        /// </summary>
        /// <param name="signingServiceIpAddress">Signing service IP address</param>
        /// <param name="signingServicePort">Signing service port</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        /// <param name="bufferSize">size of buffer to be used when receiving data</param>
        public TcpKsiServiceProtocol(IPAddress signingServiceIpAddress, ushort signingServicePort, uint? requestTimeout = null, uint? bufferSize = null)
            : this(signingServiceIpAddress, signingServicePort, null, null, requestTimeout, bufferSize)
        {
        }

        /// <summary>
        ///    Begin signing request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service async result</returns>
        public IAsyncResult BeginSign(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            CheckAggregatorRequestRunner();
            return _aggregatorRequestManager.BeginSign(data, requestId, callback, asyncState);
        }

        /// <summary>
        ///       Begin aggregator configuration request.
        /// </summary>
        /// <param name="data">aggregation request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when creating signature is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service async result</returns>
        public IAsyncResult BeginGetAggregatorConfig(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            CheckAggregatorRequestRunner();
            return _aggregatorRequestManager.BeginGetAggregatorConfig(data, requestId, callback, asyncState);
        }

        /// <summary>
        ///     End signing request.
        /// </summary>
        /// <param name="ar">TCP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndSign(IAsyncResult ar)
        {
            CheckAggregatorRequestRunner();
            return _aggregatorRequestManager.EndSign(ar);
        }

        /// <summary>
        ///     End aggregator configuration request.
        /// </summary>
        /// <param name="ar">async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndGetAggregatorConfig(IAsyncResult ar)
        {
            CheckAggregatorRequestRunner();
            return _aggregatorRequestManager.EndGetAggregatorConfig(ar);
        }

        /// <summary>
        ///     Begin extending request.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when extending request is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service async result</returns>
        public IAsyncResult BeginExtend(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            CheckAExtenderRequestRunner();
            return _extenderRequestManager.BeginExtend(data, requestId, callback, asyncState);
        }

        /// <summary>
        ///     Begin extender configuration request.
        /// </summary>
        /// <param name="data">extending request bytes</param>
        /// <param name="requestId">request id</param>
        /// <param name="callback">callback when extending request is finished</param>
        /// <param name="asyncState">async state object</param>
        /// <returns>TCP KSI service async result</returns>
        public IAsyncResult BeginGetExtenderConfig(byte[] data, ulong requestId, AsyncCallback callback, object asyncState)
        {
            CheckAExtenderRequestRunner();
            return _extenderRequestManager.BeginGetExtenderConfig(data, requestId, callback, asyncState);
        }

        /// <summary>
        ///     End extend.
        /// </summary>
        /// <param name="asyncResult">TCP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndExtend(IAsyncResult asyncResult)
        {
            CheckAExtenderRequestRunner();
            return _extenderRequestManager.EndExtend(asyncResult);
        }

        /// <summary>
        ///     End extender configuration request.
        /// </summary>
        /// <param name="asyncResult">TCP KSI service async result</param>
        /// <returns>response bytes</returns>
        public byte[] EndGetExtenderConfig(IAsyncResult asyncResult)
        {
            CheckAExtenderRequestRunner();
            return _extenderRequestManager.EndGetExtenderConfig(asyncResult);
        }

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

            _isDisposed = true;
            _aggregatorRequestManager?.Dispose();
            _extenderRequestManager?.Dispose();
        }

        private void CheckAggregatorRequestRunner()
        {
            if (_aggregatorRequestManager == null)
            {
                throw new KsiServiceProtocolException("Signing service IP address is missing.");
            }
        }

        private void CheckAExtenderRequestRunner()
        {
            if (_extenderRequestManager == null)
            {
                throw new KsiServiceProtocolException("Extend service IP address is missing.");
            }
        }
    }
}