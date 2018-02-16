/*
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
using System.IO;
using System.Threading;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Hashing;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     KSI service async result.
    /// </summary>
    public class KsiServiceAsyncResult : IAsyncResult, IDisposable
    {
        private readonly AsyncCallback _callback;
        private readonly object _lock;
        private readonly ManualResetEvent _waitHandle;
        private bool _isCompleted;
        private bool _isDisposed;

        /// <summary>
        /// Create KSI service async result instance
        /// </summary>
        /// <param name="postData">Posted bytes</param>
        /// <param name="requestId">Request ID</param>
        /// <param name="callback">callback when KSI request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        public KsiServiceAsyncResult(byte[] postData, ulong requestId, AsyncCallback callback, object asyncState)
        {
            PostData = postData;
            RequestId = requestId;
            _callback = callback;
            AsyncState = asyncState;
            _isCompleted = false;
            _lock = new object();
            _waitHandle = new ManualResetEvent(false);
            ResultStream = new MemoryStream();
        }

        /// <summary>
        /// Request ID
        /// </summary>
        public ulong RequestId { get; }

        /// <summary>
        /// The level value of the aggregation tree node to be signed
        /// </summary>
        public uint? Level { get; set; }

        /// <summary>
        /// Data hash to be signed
        /// </summary>
        public DataHash DocumentHash { get; set; }

        /// <summary>
        /// Posted bytes
        /// </summary>
        public byte[] PostData { get; }

        /// <summary>
        /// Result byte stream
        /// </summary>
        public MemoryStream ResultStream { get; set; }

        /// <summary>
        /// Returns true if error is thrown
        /// </summary>
        public bool HasError => Error != null;

        /// <summary>
        /// Error thrown
        /// </summary>
        public KsiServiceProtocolException Error { get; set; }

        /// <summary>
        /// Gets a user-defined object that qualifies or contains information about an asynchronous operation.
        /// </summary>
        /// <returns>
        /// A user-defined object that qualifies or contains information about an asynchronous operation.
        /// </returns>
        public object AsyncState { get; }

        /// <summary>
        /// Gets a <see cref="T:System.Threading.WaitHandle"/> that is used to wait for an asynchronous operation to complete.
        /// </summary>
        /// <returns>
        /// A <see cref="T:System.Threading.WaitHandle"/> that is used to wait for an asynchronous operation to complete.
        /// </returns>
        public WaitHandle AsyncWaitHandle
        {
            get
            {
                lock (_lock)
                {
                    if (_isDisposed)
                    {
                        throw new KsiServiceException("Cannot get AsyncWaitHandle property of a disposed object.");
                    }
                    return _waitHandle;
                }
            }
        }

        /// <summary>
        /// Gets a value that indicates whether the asynchronous operation completed synchronously.
        /// </summary>
        /// <returns>
        /// true if the asynchronous operation completed synchronously; otherwise, false.
        /// </returns>
        public bool CompletedSynchronously => false;

        /// <summary>
        /// Gets a value that indicates whether the asynchronous operation has completed.
        /// </summary>
        /// <returns>
        /// true if the operation is complete; otherwise, false.
        /// </returns>
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

        /// <summary>
        /// True if the instance is disposed
        /// </summary>
        public bool IsDisposed => _isDisposed;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            lock (_lock)
            {
                _isDisposed = true;
                _waitHandle.Close();
                ResultStream?.Dispose();
            }
        }

        /// <summary>
        /// Complete the async result
        /// </summary>
        public void SetComplete()
        {
            lock (_lock)
            {
                if (_isDisposed)
                {
                    return;
                }

                if (!_isCompleted)
                {
                    _isCompleted = true;
                    _callback?.Invoke(this);
                }

                if (!_waitHandle.Set())
                {
                    throw new KsiServiceProtocolException("WaitHandle completion failed");
                }
            }
        }
    }
}