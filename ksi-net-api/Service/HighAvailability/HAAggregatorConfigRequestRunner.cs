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
using NLog;

namespace Guardtime.KSI.Service.HighAvailability
{
    /// <summary>
    /// Class that is resposible for running high availablity sub-service aggregator configuration requests and giving consolidated successful sub-service results as a result.
    /// </summary>
    public class HAAggregatorConfigRequestRunner : HARequestRunner
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        private const ulong MinMaxRequests = 0;
        private const ulong MaxMaxRequests = 16000;
        private const ulong MinMaxLevel = 0;
        private const ulong MaxMaxLevel = 20;
        private const ulong MinAggegationPeriod = 100;
        private const ulong MaxAggegationPeriod = 20000;

        /// <summary>
        /// Create high availability aggregator configuration request runner instance.
        /// </summary>
        /// <param name="subServices">List of sub-services</param>
        public HAAggregatorConfigRequestRunner(IList<IKsiService> subServices) : base(subServices, true)
        {
        }

        /// <summary>
        /// Begin sub-service aggregator configuration request.
        /// </summary>
        /// <param name="service">sub-service</param>
        protected override IAsyncResult SubServiceBeginRequest(IKsiService service)
        {
            return service.BeginGetAggregatorConfig(null, null);
        }

        /// <summary>
        /// End sub-service aggregator configuration request.
        /// </summary>
        /// <param name="service">sub-service</param>
        /// <param name="asyncResult">async result</param>
        protected override object SubServiceEndRequest(IKsiService service, IAsyncResult asyncResult)
        {
            return service.EndGetAggregatorConfig(asyncResult);
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
        /// Ends HA aggregator configuration request and returns consolidated successful sub-service configurations.
        /// </summary>
        /// <param name="asyncResult"></param>
        /// <returns></returns>
        public AggregatorConfig EndGetAggregatorConfig(HAAsyncResult asyncResult)
        {
            object[] list = EndRequestMulti(asyncResult);
            AggregatorConfig config = null;

            foreach (object obj in list)
            {
                AggregatorConfig conf = obj as AggregatorConfig;

                if (conf == null)
                {
                    throw new HAKsiServiceException(string.Format("Invalid request result object. Expected type: AggregatorConfig; Received type: {0}",
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
        public static AggregatorConfig MergeConfigs(AggregatorConfig currentConfig, AggregatorConfig newConfig)
        {
            if (newConfig == null)
            {
                throw new ArgumentNullException(nameof(newConfig));
            }

            ulong? maxLevel = GetMergedMaxLevel(currentConfig?.MaxLevel, newConfig.MaxLevel);
            ulong? aggregationAlgorithm = currentConfig?.AggregationAlgorithm ?? newConfig.AggregationAlgorithm;
            ulong? aggregationPeriod = GetMergedAggregationPeriod(currentConfig?.AggregationPeriod, newConfig.AggregationPeriod);
            ulong? maxRequests = GetMergedMaxRequests(currentConfig?.MaxRequests, newConfig.MaxRequests);

            return new AggregatorConfig(
                maxLevel,
                aggregationAlgorithm,
                aggregationPeriod,
                maxRequests,
                currentConfig?.ParentsUris == null || currentConfig.ParentsUris.Count == 0 ? newConfig.ParentsUris : currentConfig.ParentsUris);
        }

        private static ulong? GetMergedMaxLevel(ulong? currentMaxLevel, ulong? newMaxLevel)
        {
            if (!newMaxLevel.HasValue)
            {
                return currentMaxLevel;
            }

            if (newMaxLevel > MaxMaxLevel)
            {
                Logger.Warn("Received max level '{0}' from an aggregator. Will not use it as only values between {1} and {2} are considered sane.", newMaxLevel,
                    MinMaxLevel, MaxMaxLevel);
                return currentMaxLevel;
            }

            if (currentMaxLevel == null || currentMaxLevel < newMaxLevel)
            {
                return newMaxLevel;
            }
            return currentMaxLevel;
        }

        private static ulong? GetMergedMaxRequests(ulong? currentMaxRequests, ulong? newMaxRequests)
        {
            if (!newMaxRequests.HasValue)
            {
                return currentMaxRequests;
            }

            if (newMaxRequests > MaxMaxRequests)
            {
                Logger.Warn("Received max requests '{0}' from an aggregator. Will not use it as only values between {1} and {2} are considered sane.", newMaxRequests,
                    MinMaxRequests, MaxMaxRequests);
                return currentMaxRequests;
            }

            if (currentMaxRequests == null || currentMaxRequests < newMaxRequests)
            {
                currentMaxRequests = newMaxRequests;
            }
            return currentMaxRequests;
        }

        private static ulong? GetMergedAggregationPeriod(ulong? currentAggregationPeriod, ulong? newAggregationPeriod)
        {
            if (!newAggregationPeriod.HasValue)
            {
                return currentAggregationPeriod;
            }

            if (newAggregationPeriod < MinAggegationPeriod || newAggregationPeriod > MaxAggegationPeriod)
            {
                Logger.Warn("Received aggregation period '{0}' from an aggregator. Will not use it as only values between {1} and {2} are considered sane.",
                    newAggregationPeriod,
                    MinAggegationPeriod, MaxAggegationPeriod);
                return currentAggregationPeriod;
            }

            if (currentAggregationPeriod == null || currentAggregationPeriod > newAggregationPeriod)
            {
                currentAggregationPeriod = newAggregationPeriod;
            }
            return currentAggregationPeriod;
        }
    }
}