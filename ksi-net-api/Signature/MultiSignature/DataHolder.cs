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

namespace Guardtime.KSI.Signature.MultiSignature
{
    /// <summary>
    /// Class for holding TLV elements in multi-signature.
    /// </summary>
    public class DataHolder<T1, T2> : Dictionary<T1, T2> where T2 : class
    {
        /// <summary>
        /// Get or set an element.
        /// </summary>
        /// <param name="key"></param>
        public new T2 this[T1 key]
        {
            get { return ContainsKey(key) ? base[key] : null; }
            set { base[key] = value; }
        }

        /// <summary>
        /// Add an element. If such key already exists then element will not be added.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="value"></param>
        public new void Add(T1 key, T2 value)
        {
            if (value == null)
            {
                return;
            }

            if (!ContainsKey(key))
            {
                base.Add(key, value);
            }
        }

        /// <summary>
        /// Remove element
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public new bool Remove(T1 key)
        {
            return !ContainsKey(key) || base.Remove(key);
        }
    }
}