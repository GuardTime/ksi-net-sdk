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

namespace Guardtime.KSI.Parser
{
    /// <summary>
    /// Class for holding child tag count values.
    /// </summary>
    public class TagCounter
    {
        readonly Dictionary<uint, int> _values = new Dictionary<uint, int>();

        /// <summary>
        ///     Get or set count values
        /// </summary>
        /// <param name="key">count key</param>
        /// <returns>count value corresponding to the given key</returns>
        public int this[uint key]
        {
            get { return _values.ContainsKey(key) ? _values[key] : 0; }
            set
            {
                if (_values.ContainsKey(key))
                {
                    _values[key] += value;
                }
                else
                {
                    _values.Add(key, value);
                }
            }
        }
    }
}