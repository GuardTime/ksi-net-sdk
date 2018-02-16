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

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Class containing KSI service response payload info (payload type and request ID)
    /// </summary>
    public class KsiServiceResponsePayloadInfo
    {
        /// <summary>
        /// Create KSI service response payload info
        /// </summary>
        /// <param name="responsePayloadType"></param>
        /// <param name="requestId"></param>
        public KsiServiceResponsePayloadInfo(KsiServiceResponsePayloadType responsePayloadType, ulong? requestId = null)
        {
            ResponsePayloadType = responsePayloadType;
            RequestId = requestId;
        }

        /// <summary>
        /// TCP response payload type
        /// </summary>
        public KsiServiceResponsePayloadType ResponsePayloadType { get; }

        /// <summary>
        /// Request ID
        /// </summary>
        public ulong? RequestId { get; }

        /// <summary>
        /// Returns a string that represents the current object.
        /// </summary>
        public override string ToString() => string.Format("[Type: {0}; RequestId: {1}]", ResponsePayloadType, RequestId);
    }
}