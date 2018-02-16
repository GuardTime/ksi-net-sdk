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
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Service
{
    /// <summary>
    /// Class holding aggregator configuration changed event information. 
    /// </summary>
    public class AggregatorConfigChangedEventArgs : EventArgs
    {
        /// <summary>
        /// Exception thrown while processing agregation configuration request.
        /// </summary>
        public KsiException Exception { get; set; }

        /// <summary>
        /// New aggregator configuration.
        /// </summary>
        public AggregatorConfig AggregatorConfig { get; }

        /// <summary>
        /// KsiService that made the aggregator configuration request.
        /// </summary>
        public IKsiService KsiService { get; }

        /// <summary>
        /// Create aggregator configuration changed event arguments class instance.
        /// </summary>
        /// <param name="exception">Exception thrown while processing aggregator configuration request</param>
        /// <param name="ksiService">KsiService that made the aggregator configuration request</param>
        public AggregatorConfigChangedEventArgs(KsiException exception, IKsiService ksiService)

        {
            Exception = exception;
            KsiService = ksiService;
        }

        /// <summary>
        /// Create aggregator configuration changed event arguments class instance.
        /// </summary>
        /// <param name="aggregatorConfig">New aggregator configuration</param>
        /// <param name="ksiService">KsiService that made the aggregator configuration request</param>
        public AggregatorConfigChangedEventArgs(AggregatorConfig aggregatorConfig, IKsiService ksiService = null)
        {
            AggregatorConfig = aggregatorConfig;
            KsiService = ksiService;
        }
    }
}