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

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Paylaod types returned by KSI service.
    /// </summary>
    public enum KsiServiceResponsePayloadType
    {
        /// <summary>
        /// Aggregation request response payload
        /// </summary>
        Aggregation,

        /// <summary>
        /// Aggregator configuration request response payload
        /// </summary>
        AggregatorConfig,

        /// <summary>
        /// Extending request response payload
        /// </summary>
        Extending,

        /// <summary>
        /// Extender configuration request response payload
        /// </summary>
        ExtenderConfig,

        /// <summary>
        /// Error payload
        /// </summary>
        Error
    };
}