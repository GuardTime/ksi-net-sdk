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
using Guardtime.KSI.Service;

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     Exception inidcating that HA service sub-request failed.
    /// </summary>
    [Serializable]
    public class HAKsiSubServiceException : KsiException
    {
        /// <summary>
        /// Sub-service that threw the exception
        /// </summary>
        public IKsiService ThrownBySubService { get; set; }

        /// <summary>
        ///     Create new HA KSI sub-service exception.
        /// </summary>
        /// <param name="thrownBySubService">Sub-service that threw the exception</param>
        /// <param name="message">Exception message</param>
        public HAKsiSubServiceException(IKsiService thrownBySubService, string message) : base(message)
        {
            ThrownBySubService = thrownBySubService;
        }

        /// <summary>
        ///     Create new HA KSI sub-service exception.
        /// </summary>
        /// <param name="thrownBySubService">Sub-service that threw the exception</param>
        /// <param name="message">Exception message</param>
        /// <param name="innerExceptions">Inner exceptions</param>
        public HAKsiSubServiceException(IKsiService thrownBySubService, string message, Exception innerExceptions) : base(message, innerExceptions)
        {
            ThrownBySubService = thrownBySubService;
        }
    }
}