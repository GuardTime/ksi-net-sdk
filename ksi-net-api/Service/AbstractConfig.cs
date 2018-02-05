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
using System.Collections.ObjectModel;

namespace Guardtime.KSI.Service
{
    /// <summary>
    ///     Abstract configuration data.
    /// </summary>
    public abstract class AbstractConfig : IEquatable<AbstractConfig>
    {
        /// <summary>
        /// Create new configuration data instance
        /// </summary>
        /// <param name="parentsUris">Parent server URI (may be several parent servers)</param>
        protected AbstractConfig(IList<string> parentsUris)
        {
            if (parentsUris != null)
            {
                ParentsUris = new ReadOnlyCollection<string>(parentsUris);
            }
        }

        /// <summary>
        /// Parent server URI (may be several parent servers)
        /// </summary>
        public ReadOnlyCollection<string> ParentsUris { get; }

        /// <summary>
        ///     Compare current config against another config.
        /// </summary>
        /// <param name="config">config to copare against</param>
        /// <returns>true if objects are equal</returns>
        public bool Equals(AbstractConfig config)
        {
            if (config == null)
            {
                return false;
            }

            if (ReferenceEquals(this, config))
            {
                return true;
            }

            if (GetType() != config.GetType())
            {
                return false;
            }

            if (ParentsUris == null && config.ParentsUris != null)
            {
                return false;
            }

            if (ParentsUris != null && config.ParentsUris == null)
            {
                return false;
            }

            if (ParentsUris != null && config.ParentsUris != null)
            {
                if (ParentsUris.Count != config.ParentsUris.Count)
                {
                    return false;
                }

                for (int i = 0; i < ParentsUris.Count; i++)
                {
                    if (ParentsUris[i] != config.ParentsUris[i])
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        /// <summary>
        /// Get string that represents parent URIs
        /// </summary>
        /// <returns></returns>
        protected string GetParentUrisString()
        {
            string parentUrisString = null;

            if (ParentsUris != null)
            {
                foreach (string uri in ParentsUris)
                {
                    if (parentUrisString != null)
                    {
                        parentUrisString += ", ";
                    }

                    parentUrisString += "'" + uri + "'";
                }
            }
            return parentUrisString;
        }
    }
}