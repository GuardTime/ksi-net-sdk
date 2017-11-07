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
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;
using NLog;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// Class that is resposible for running high availablity sub-service extender configuration requests and giving consolidated successful sub-service results as a result.
    /// </summary>
    public class HAExtenderConfigRequestRunner : HARequestRunner
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private const ulong MinMaxRequests = 0;
        private const ulong MaxMaxRequests = 16000;
        private const ulong MinCalendarTime = 1136073600; // 2006-01-01 00:00:00

        /// <summary>
        /// Create high availability extender configuration request runner instance.
        /// </summary>
        /// <param name="subServices">List of sub-services</param>
        public HAExtenderConfigRequestRunner(IList<IKsiService> subServices) : base(subServices, true)
        {
        }

        /// <summary>
        /// Begin sub-service extender configuration request.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override IAsyncResult SubServiceBeginRequest(IKsiService service)
        {
            return service.BeginGetExtenderConfig(null, null);
        }

        /// <summary>
        /// End sub-service extender configuration request.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <param name="asyncResult">async result</param>
        protected override object SubServiceEndRequest(IKsiService service, IAsyncResult asyncResult)
        {
            return service.EndGetExtenderConfig(asyncResult);
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
        /// Ends HA extender configuration request and returns consolidated successful sub-service configurations.
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns></returns>
        public ExtenderConfig EndGetExtenderConfig(HAAsyncResult asyncResult)
        {
            object[] list = EndRequestMulti(asyncResult);
            ExtenderConfig config = null;

            foreach (object obj in list)
            {
                ExtenderConfig conf = obj as ExtenderConfig;

                if (conf == null)
                {
                    throw new HAKsiServiceException(string.Format("Invalid request result object. Expected type: ExtenderConfig; Received type: {0}",
                        obj?.GetType().ToString() ?? ""));
                }

                config = MergeConfigs(config, conf);
            }

            return config;
        }

        /// <summary>
        /// Merge two configurations into one taking into account consolidation rules.
        /// </summary>
        /// <param name="currentConfig"></param>
        /// <param name="newConfig"></param>
        /// <returns></returns>
        public static ExtenderConfig MergeConfigs(ExtenderConfig currentConfig, ExtenderConfig newConfig)
        {
            if (newConfig == null)
            {
                throw new ArgumentNullException(nameof(newConfig));
            }

            ulong? maxRequests = GetMergedMaxRequests(currentConfig?.MaxRequests, newConfig.MaxRequests);
            ulong? calendarFirstTime = GetMergedCalendarFirstTime(currentConfig?.CalendarFirstTime, newConfig.CalendarFirstTime);
            ulong? calendarLastTime = GetMergedCalendarLastTime(currentConfig?.CalendarLastTime, newConfig.CalendarLastTime, calendarFirstTime);

            return new ExtenderConfig(
                maxRequests,
                currentConfig?.ParentsUris == null || currentConfig.ParentsUris.Count == 0 ? newConfig.ParentsUris : currentConfig.ParentsUris,
                calendarFirstTime,
                calendarLastTime);
        }

        private static ulong? GetMergedMaxRequests(ulong? currentMaxRequests, ulong? newMaxRequests)
        {
            if (!newMaxRequests.HasValue)
            {
                return currentMaxRequests;
            }

            if (newMaxRequests > MaxMaxRequests)
            {
                Logger.Warn("Received max requests '{0}' from an extender. Will not use it as only values between {1} and {2} are considered sane.", newMaxRequests,
                    MinMaxRequests, MaxMaxRequests);
                return currentMaxRequests;
            }

            if (currentMaxRequests == null || currentMaxRequests < newMaxRequests)
            {
                currentMaxRequests = newMaxRequests;
            }
            return currentMaxRequests;
        }

        private static ulong? GetMergedCalendarFirstTime(ulong? currentCalendarFirstTime, ulong? newCalendarFirstTime)
        {
            if (!newCalendarFirstTime.HasValue)
            {
                return currentCalendarFirstTime;
            }

            if (newCalendarFirstTime < MinCalendarTime)
            {
                Logger.Warn("Received calendar first time '{0}' from an extender. Will not use it as values before {1} ({2}) are not sane.", newCalendarFirstTime, MinCalendarTime,
                    Util.ConvertUnixTimeToDateTime(MinCalendarTime));
                return currentCalendarFirstTime;
            }

            if (currentCalendarFirstTime == null || currentCalendarFirstTime > newCalendarFirstTime)
            {
                currentCalendarFirstTime = newCalendarFirstTime;
            }
            return currentCalendarFirstTime;
        }

        private static ulong? GetMergedCalendarLastTime(ulong? currentCalendarLastTime, ulong? newCalendarLastTime, ulong? calendarFirstTime)
        {
            if (!newCalendarLastTime.HasValue)
            {
                return currentCalendarLastTime;
            }

            if (newCalendarLastTime < MinCalendarTime)
            {
                Logger.Warn("Received calendar last time '{0}' from an extender. Will not use it as values before {1} ({2}) are not sane.", newCalendarLastTime, MinCalendarTime,
                    Util.ConvertUnixTimeToDateTime(MinCalendarTime));
                return currentCalendarLastTime;
            }

            if (calendarFirstTime.HasValue && newCalendarLastTime < calendarFirstTime)
            {
                Logger.Warn("Received calendar last time '{0}' from an extender. Will not use it as values before calendar first time ({1}) are not sane.", newCalendarLastTime,
                    calendarFirstTime);
                return currentCalendarLastTime;
            }

            if (currentCalendarLastTime == null || currentCalendarLastTime < newCalendarLastTime)
            {
                currentCalendarLastTime = newCalendarLastTime;
            }
            return currentCalendarLastTime;
        }
    }
}