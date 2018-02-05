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

using System.Collections.Generic;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Class containing extender configuration data.
    /// </summary>
    public sealed class ExtenderConfig : AbstractConfig
    {
        /// <summary>
        /// Create new extender configuration instance
        /// </summary>
        public ExtenderConfig(ExtenderConfigResponsePayload payload) : base(payload.ParentsUris)
        {
            MaxRequests = payload.MaxRequests;
            CalendarFirstTime = payload.CalendarFirstTime;
            CalendarLastTime = payload.CalendarLastTime;
        }

        /// <summary>
        /// Create new extender configuration data instance
        /// </summary>
        /// <param name="maxRequests">Maximum number of requests the client is allowed to send within one second</param>
        /// <param name="parentsUris">Parent server URI (may be several parent servers)</param>
        /// <param name="calendarFirstTime">Aggregation time of the oldest calendar record the extender has</param>
        /// <param name="calendarLastTime">Aggregation time of the newest calendar record the extender has</param>
        public ExtenderConfig(ulong? maxRequests, IList<string> parentsUris, ulong? calendarFirstTime, ulong? calendarLastTime) : base(parentsUris)
        {
            MaxRequests = maxRequests;
            CalendarFirstTime = calendarFirstTime;
            CalendarLastTime = calendarLastTime;
        }

        /// <summary>
        /// Maximum number of requests the client is allowed to send within one second
        /// </summary>
        public ulong? MaxRequests { get; }

        /// <summary>
        /// Aggregation time of the oldest calendar record the extender has
        /// </summary>
        public ulong? CalendarFirstTime { get; }

        /// <summary>
        /// Aggregation time of the newest calendar record the extender has
        /// </summary>
        public ulong? CalendarLastTime { get; }

        /// <summary>
        ///     Compare current extender config against another config.
        /// </summary>
        /// <param name="config">extender config</param>
        /// <returns>true if objects are equal</returns>
        public bool Equals(ExtenderConfig config)
        {
            if (!base.Equals(config))
            {
                return false;
            }

            if (MaxRequests != config.MaxRequests)
            {
                return false;
            }

            if (CalendarFirstTime != config.CalendarFirstTime)
            {
                return false;
            }

            if (CalendarLastTime != config.CalendarLastTime)
            {
                return false;
            }

            return true;
        }

        /// <summary>Returns a string that represents the current object.</summary>
        public override string ToString()
        {
            return string.Format("ExtenderConfig [{0},{1},{2},[{3}]]", MaxRequests?.ToString() ?? "null", CalendarFirstTime?.ToString() ?? "null",
                CalendarLastTime?.ToString() ?? "null", GetParentUrisString());
        }
    }
}