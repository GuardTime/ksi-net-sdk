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
using Guardtime.KSI.Publication;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// Class that is resposible for running high availablity sub-service publications file requests and giving the first successful sub-service result as a result.
    /// </summary>
    public class HAPublicationsFileRequestRunner : HARequestRunner
    {
        /// <summary>
        /// Create high availability publications file request runner instance.
        /// </summary>
        /// <param name="subServices">List of sub-services</param>
        public HAPublicationsFileRequestRunner(IList<IKsiService> subServices) : base(subServices)
        {
        }

        /// <summary>
        /// Begin sub-service publications file request.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override IAsyncResult SubServiceBeginRequest(IKsiService service)
        {
            return service.BeginGetPublicationsFile(null, null);
        }

        /// <summary>
        /// End sub-service publications file request.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <param name="asyncResult">async result</param>
        protected override object SubServiceEndRequest(IKsiService service, IAsyncResult asyncResult)
        {
            return service.EndGetPublicationsFile(asyncResult);
        }

        /// <summary>
        /// Returns a string that represents the given publications file sub-service.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override string SubServiceToString(IKsiService service)
        {
            return "Publications file service: " + service.PublicationsFileLocation;
        }

        /// <summary>
        /// Ends HA publications file request and returns the first successful sub-service response.
        /// </summary>
        /// <param name="haAsyncResult">HA async result</param>
        public IPublicationsFile EndPublucationsFile(HAAsyncResult haAsyncResult)
        {
            return EndRequest<IPublicationsFile>(haAsyncResult);
        }
    }
}