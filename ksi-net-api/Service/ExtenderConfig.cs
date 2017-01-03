/*
 * Copyright 2013-2016 Guardtime, Inc.
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

using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Class containing extender configuration data.
    /// </summary>
    public sealed class ExtenderConfig
    {
        /// <summary>
        /// Create new extender configuration instance
        /// </summary>
        public ExtenderConfig(ExtenderConfigResponsePayload payload)
        {
            MaxRequests = payload.MaxRequests;
            ParentsUris = new ReadOnlyCollection<string>(payload.ParentsUris);
            CalendarFirstTime = payload.CalendarFirstTime;
            CalendarLastTime = payload.CalendarLastTime;
        }

        /// <summary>
        /// Maximum number of requests the client is allowed to send within one second
        /// </summary>
        public ulong? MaxRequests { get; }

        /// <summary>
        /// Parent server URI (may be several parent servers)
        /// </summary>
        public IList<string> ParentsUris { get; }

        /// <summary>
        /// Aggregation time of the oldest calendar record the extender has
        /// </summary>
        public ulong? CalendarFirstTime { get; }

        /// <summary>
        /// Aggregation time of the newest calendar record the extender has
        /// </summary>
        public ulong? CalendarLastTime { get; }
    }
}