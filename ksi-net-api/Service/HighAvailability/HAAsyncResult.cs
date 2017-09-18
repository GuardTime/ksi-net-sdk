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
using System.Threading;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// High availablity KSI service async result.
    /// </summary>
    public class HAAsyncResult : IAsyncResult, IDisposable
    {
        private readonly AsyncCallback _callback;
        private readonly object _lock;
        private readonly object _resultTlvLock;

        private readonly ManualResetEvent _waitHandle;
        private ManualResetEvent _endCallWaitHandle;
        private bool _isCompleted;
        private readonly List<object> _resultTlvs;

        /// <summary>
        /// Create high availablity KSI service async result instance.
        /// </summary>
        /// <param name="callback">callback when HA request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <param name="requestRunner"></param>
        public HAAsyncResult(AsyncCallback callback, object asyncState, HARequestRunner requestRunner)
        {
            if (requestRunner == null)
            {
                throw new ArgumentNullException(nameof(requestRunner));
            }

            _callback = callback;
            AsyncState = asyncState;
            RequestRunner = requestRunner;

            _isCompleted = false;

            _lock = new object();
            _resultTlvLock = new object();
            _resultTlvs = new List<object>();
            _waitHandle = new ManualResetEvent(false);
        }

        /// <summary>
        /// Add result TLV.
        /// </summary>
        /// <param name="tlv"></param>
        public void AddResultTlv(object tlv)
        {
            if (IsCompleted)
            {
                return;
            }

            lock (_resultTlvLock)
            {
                _resultTlvs.Add(tlv);
            }
        }

        /// <summary>
        /// Count of result TLVs.
        /// </summary>
        /// <returns></returns>
        public int ResultTlvCount
        {
            get
            {
                lock (_resultTlvLock)
                {
                    return _resultTlvs.Count;
                }
            }
        }

        /// <summary>
        /// Get array of result TLVs.
        /// </summary>
        /// <returns></returns>
        public object[] GetResultTlvs()
        {
            lock (_resultTlvLock)
            {
                return _resultTlvs.ToArray();
            }
        }

        /// <summary>
        /// Sub-service errors.
        /// </summary>
        public List<HAKsiSubServiceException> Errors { get; } = new List<HAKsiSubServiceException>();

        /// <summary>
        /// Gets a user-defined object that qualifies or contains information about an asynchronous operation.
        /// </summary>
        public object AsyncState { get; }

        /// <summary>
        /// Gets a <see cref="T:System.Threading.WaitHandle"/> that is used to wait for an asynchronous operation to complete.
        /// </summary>
        public WaitHandle AsyncWaitHandle => _waitHandle;

        /// <summary>
        /// Gets a <see cref="T:System.Threading.WaitHandle"/> that is used to wait for HA end request method call. 
        /// It is used when multiple request end method exist, eg. signing request can end with EndSign or GetSignResponsePayload.
        /// </summary>
        public ManualResetEvent EndCallWaitHandle => _endCallWaitHandle;

        /// <summary>
        /// Gets a value that indicates whether the asynchronous operation completed synchronously.
        /// </summary>
        public bool CompletedSynchronously => false;

        /// <summary>
        /// Get high availability request runner.
        /// </summary>
        public HARequestRunner RequestRunner { get; }

        /// <summary>
        /// Initalize EndCallWaitHandle
        /// </summary>
        public void InitEndCallWaitHandle()
        {
            _endCallWaitHandle = new ManualResetEvent(false);
        }

        /// <summary>
        /// Gets a value that indicates whether the asynchronous operation has completed.
        /// </summary>
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
        /// Releasing unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            _waitHandle.Close();
        }

        /// <summary>
        /// Set async operation as completed.
        /// </summary>
        public void SetComplete()
        {
            lock (_lock)
            {
                if (!_isCompleted)
                {
                    _isCompleted = true;
                    _callback?.Invoke(this);
                }
            }

            if (!_waitHandle.Set())
            {
                throw new KsiException("WaitHandle completion failed.");
            }
        }
    }
}