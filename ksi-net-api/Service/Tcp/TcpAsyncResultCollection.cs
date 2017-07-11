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

namespace Guardtime.KSI.Service.Tcp
{
    /// <summary>
    /// Syncronized collection containing TcpKsiServiceProtocol asyncResults.
    /// </summary>
    public class TcpAsyncResultCollection
    {
        readonly Dictionary<ulong, TcpKsiServiceProtocolAsyncResult> _list = new Dictionary<ulong, TcpKsiServiceProtocolAsyncResult>();
        private readonly object _syncObj = new object();

        /// <summary>
        /// Add new async result into the collection
        /// </summary>
        /// <param name="key">The key of the element to add</param>
        /// <param name="asyncResult">Asycn result to add</param>
        public void Add(ulong key, TcpKsiServiceProtocolAsyncResult asyncResult)
        {
            lock (_syncObj)
            {
                _list.Add(key, asyncResult);
            }
        }

        /// <summary>
        /// Remove async result from the collection
        /// </summary>
        /// <param name="asyncResult">Async result to removed</param>
        public void Remove(TcpKsiServiceProtocolAsyncResult asyncResult)
        {
            lock (_syncObj)
            {
                if (_list.ContainsKey(asyncResult.RequestId))
                {
                    _list.Remove(asyncResult.RequestId);
                }
            }
        }

        /// <summary>
        /// Get all keys
        /// </summary>
        /// <returns></returns>
        public ulong[] GetKeys()
        {
            lock (_syncObj)
            {
                ulong[] keys = new ulong[_list.Keys.Count];
                _list.Keys.CopyTo(keys, 0);
                return keys;
            }
        }

        /// <summary>
        /// Count of elements in collection
        /// </summary>
        /// <returns></returns>
        public int Count()
        {
            lock (_syncObj)
            {
                return _list.Count;
            }
        }

        /// <summary>
        /// Get specific async result
        /// </summary>
        /// <param name="key">The key of the element to return</param>
        /// <returns></returns>
        public TcpKsiServiceProtocolAsyncResult GetValue(ulong key)
        {
            lock (_syncObj)
            {
                return _list.ContainsKey(key) ? _list[key] : null;
            }
        }

        /// <summary>
        /// Clear collection
        /// </summary>
        public void Clear()
        {
            lock (_syncObj)
            {
                _list.Clear();
            }
        }
    }
}