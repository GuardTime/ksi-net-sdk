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
using Guardtime.KSI.Hashing;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// Class that is resposible for running high availablity sub-service signing requests and giving the first successful sub-service result as a result.
    /// </summary>
    public class HASignRequestRunner : HARequestRunner
    {
        private readonly DataHash _hash;
        private readonly uint _level;
        private bool _returnResponsePayload;

        /// <summary>
        /// Create high availability signing request runner instance.
        /// </summary>
        /// <param name="subServices">List of sub-services</param>
        /// <param name="hash">data hash to be signed</param>
        /// <param name="level">the level value of the aggregation tree node</param>
        public HASignRequestRunner(IList<IKsiService> subServices, DataHash hash, uint level) : base(subServices)
        {
            _hash = hash;
            _level = level;
        }

        /// <summary>
        /// Begin HA request.
        /// </summary>
        /// <param name="callback">callback when HA request is finished</param>
        /// <param name="asyncState">callback async state object</param>
        /// <returns></returns>
        public HAAsyncResult BeginRequest(AsyncCallback callback, object asyncState)
        {
            return base.BeginRequest(callback, asyncState, true);
        }

        /// <summary>
        /// Begin sub-service signing request.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override IAsyncResult SubServiceBeginRequest(IKsiService service)
        {
            return service.BeginSign(_hash, _level, null, null);
        }

        /// <summary>
        /// End sub-service signing request.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <param name="asyncResult">async result</param>
        protected override object SubServiceEndRequest(IKsiService service, IAsyncResult asyncResult)
        {
            if (_returnResponsePayload)
            {
                return service.GetSignResponsePayload(asyncResult);
            }
            return service.EndSign(asyncResult);
        }

        /// <summary>
        /// Returns a string that represents the given signing sub-service.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override string SubServiceToString(IKsiService service)
        {
            return "Signing service: " + service.AggregatorAddress;
        }

        /// <summary>
        /// Ends HA signing request and returns the first successful sub-service signing response.
        /// </summary>
        /// <param name="haAsyncResult">HA async result</param>
        public SignRequestResponsePayload GetSignResponsePayload(HAAsyncResult haAsyncResult)
        {
            _returnResponsePayload = true;
            return EndRequest<SignRequestResponsePayload>(haAsyncResult);
        }

        /// <summary>
        /// Ends HA signing request and returns the first successful sub-service signing response.
        /// </summary>
        /// <param name="haAsyncResult">HA async result</param>
        public IKsiSignature EndSign(HAAsyncResult haAsyncResult)
        {
            return EndRequest<KsiSignature>(haAsyncResult);
        }
    }
}