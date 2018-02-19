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

namespace Guardtime.KSI.Service.Tcp
{
    /// <summary>
    ///     TCP KSI service async result.
    /// </summary>
    public class TcpKsiServiceAsyncResult : KsiServiceAsyncResult
    {
        /// <summary>
        /// Create TCP KSI service async result instance
        /// </summary>
        /// <param name="serviceRequestType">Service request type</param>
        /// <param name="postData">Posted bytes</param>
        /// <param name="requestId">Request ID</param>
        /// <param name="callback">callback when TCP request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        public TcpKsiServiceAsyncResult(KsiServiceRequestType serviceRequestType, byte[] postData, ulong requestId, AsyncCallback callback, object asyncState)
            : base(postData, requestId, callback, asyncState)
        {
            ServiceRequestType = serviceRequestType;
        }

        /// <summary>
        /// TCP request type
        /// </summary>
        [Obsolete("Use ServiceRequestType instead.")]
        public TcpRequestType RequestType
        {
            get
            {
                switch (ServiceRequestType)
                {
                    case KsiServiceRequestType.Sign:
                        return TcpRequestType.Aggregation;
                    case KsiServiceRequestType.AggregatorConfig:
                        return TcpRequestType.AggregatorConfig;
                    default:
                        throw new ArgumentException("Cannot convert request type: " + ServiceRequestType);
                }
            }
        }

        /// <summary>
        /// TCP request type (signing, extending, configuration request)
        /// </summary>
        public KsiServiceRequestType ServiceRequestType { get; }
    }
}