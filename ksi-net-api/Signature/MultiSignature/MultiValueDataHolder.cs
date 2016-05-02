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
    /// Abstract class for holding TLV elements in multi-signature. Enables to hold multiple values under the same key.
    /// </summary>
    public abstract class MultiValueDataHolder<TKey, TValue> : Dictionary<TKey, List<TValue>>
    {
        /// <summary>
        /// Add an element
        /// </summary>
        /// <param name="rfc3161Record"></param>
        public abstract void Add(TValue rfc3161Record);

        /// <summary>
        /// Get an element. If multiple elements exists under the same key the first will be returned.
        /// </summary>
        /// <param name="key"></param>
        public new TValue this[TKey key] => ContainsKey(key) ? base[key][0] : default(TValue);

        /// <summary>
        /// Returnes element list under given key.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        protected List<TValue> Get(TKey key)
        {
            return base[key];
        }

        /// <summary>
        /// Removes the first element under given key. It this was the last element then the key will be removed.
        /// </summary>
        /// <param name="key"></param>
        public new void Remove(TKey key)
        {
            if (!ContainsKey(key))
            {
                return;
            }

            if (base[key].Count > 1)
            {
                base[key].RemoveAt(0);
            }
            else
            {
                base.Remove(key);
            }
        }

        /// <summary>
        /// Returns all values under all keys as one list.
        /// </summary>
        /// <returns></returns>
        public List<TValue> GetAllValues()
        {
            List<TValue> result = new List<TValue>();

            foreach (TKey key in Keys)
            {
                result.AddRange(base[key]);
            }

            return result;
        }
    }
}