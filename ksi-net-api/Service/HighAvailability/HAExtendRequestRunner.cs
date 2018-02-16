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
using System.Collections.Generic;
using Guardtime.KSI.Signature;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// Class that is resposible for running high availablity sub-service extending requests and giving the first successful sub-service result as a result.
    /// </summary>
    public class HAExtendRequestRunner : HARequestRunner
    {
        private readonly ulong _aggregationTime;
        private readonly ulong? _publicationTime;

        /// <summary>
        /// Create high availability extending request runner instance.
        /// </summary>
        /// <param name="subServices">List of sub-services</param>
        /// <param name="aggregationTime">aggregation time</param>
        /// <param name="publicationTime">publication time</param>
        /// <param name="requestTimeout">request timeout in milliseconds</param>
        public HAExtendRequestRunner(IList<IKsiService> subServices, ulong aggregationTime, ulong? publicationTime,  uint requestTimeout) : base(subServices, requestTimeout)
        {
            _aggregationTime = aggregationTime;
            _publicationTime = publicationTime;
        }

        /// <summary>
        /// Begin sub-service extending request.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override IAsyncResult SubServiceBeginRequest(IKsiService service)
        {
            return _publicationTime.HasValue ? service.BeginExtend(_aggregationTime, _publicationTime.Value, null, null) : service.BeginExtend(_aggregationTime, null, null);
        }

        /// <summary>
        /// End sub-service extending request.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <param name="asyncResult">async result</param>
        protected override object SubServiceEndRequest(IKsiService service, IAsyncResult asyncResult)
        {
            return service.EndExtend(asyncResult);
        }

        /// <summary>
        /// Returns a string that represents the given extending sub-service.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override string SubServiceToString(IKsiService service)
        {
            return "Extending service: " + service.ExtenderAddress;
        }

        /// <summary>
        /// Ends HA extending request and returns the first successful sub-service extending response.
        /// </summary>
        /// <param name="haAsyncResult">HA async result</param>
        public CalendarHashChain EndExtend(HAAsyncResult haAsyncResult)
        {
            return EndRequest<CalendarHashChain>(haAsyncResult);
        }
    }
}