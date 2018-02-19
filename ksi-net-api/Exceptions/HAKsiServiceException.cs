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

namespace Guardtime.KSI.Exceptions
{
    /// <summary>
    ///     Exception inidcating that HA service request failed.
    /// </summary>
    [Serializable]
    public class HAKsiServiceException : KsiException
    {
        /// <summary>
        /// Exceptions thrown by sub-services
        /// </summary>
        public List<HAKsiSubServiceException> SubServiceExceptions { get; }

        /// <summary>
        ///     Create new HA KSI service exception.
        /// </summary>
        /// <param name="message">Exception message</param>
        public HAKsiServiceException(string message) : base(message)
        {
        }

        /// <summary>
        ///     Create new HA KSI service exception.
        /// </summary>
        /// <param name="message">Exception message</param>
        /// <param name="subServiceExceptions">Exceptions thrown by sub-services</param>
        public HAKsiServiceException(string message, List<HAKsiSubServiceException> subServiceExceptions) : base(message)
        {
            SubServiceExceptions = subServiceExceptions;
        }
    }
}