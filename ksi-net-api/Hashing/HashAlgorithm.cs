﻿/*
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
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    ///     List of supported hash functions and some convenience functions.
    /// </summary>
    public sealed partial class HashAlgorithm
    {
        /// <summary>
        ///     HashAlgorithm Status enum.
        /// </summary>
        public enum AlgorithmStatus
        {
            /// <summary>
            ///     Normal fully supported algorithm.
            /// </summary>
            Normal,

            /// <summary>
            ///     Algorithm no longer considered secure and only kept for backwards
            ///     compatibility. Should not be used in new signatures. Should trigger
            ///     verification warnings when encountered in existing signatures.
            /// </summary>
            NotTrusted,

            /// <summary>
            ///     Algorithm defined in the specification, but not yet available in the implementation.
            /// </summary>
            NotImplemented
        }

        private static readonly byte[] InvalidHashAlgorithmIds = new byte[] { 0x03, 0x7E };

        private static readonly Dictionary<string, HashAlgorithm> Lookup = new Dictionary<string, HashAlgorithm>();
        private static readonly HashAlgorithm[] Values;

        private readonly string[] _alternatives;
        private readonly ulong? _deprecatedSince;
        private readonly ulong? _obsoleteSince;

        /// <summary>
        ///     Static constructor for creating lookup table for names.
        /// </summary>
        static HashAlgorithm()
        {
            Values = new HashAlgorithm[] { Sha1, Sha2256, Ripemd160, Sha2384, Sha2512, Sha3224, Sha3256, Sha3384, Sha3512, Sm3 };

            foreach (HashAlgorithm algorithm in Values)
            {
                Lookup.Add(NameNormalize(algorithm.Name), algorithm);
                foreach (string alternative in algorithm._alternatives)
                {
                    Lookup.Add(NameNormalize(alternative), algorithm);
                }
            }
        }

        /// <summary>
        ///     Private constructor for HashAlgorithm object.
        /// </summary>
        /// <param name="name">algorithm name</param>
        /// <param name="id">algorithm Guardtime id</param>
        /// <param name="length">algorithm value length</param>
        /// <param name="status">algorithm status</param>
        /// <param name="alternatives">algorithm alternative names</param>
        /// <param name="deprecatedSince">date from which the algorithm is deprecated</param>
        /// <param name="obsoleteSince">date from which the algorithm is obsolete</param>
        private HashAlgorithm(string name, byte id, int length, AlgorithmStatus status, string[] alternatives = null, ulong? deprecatedSince = null,
                              ulong? obsoleteSince = null)
        {
            if (alternatives == null)
            {
                alternatives = new string[] { };
            }

            Name = name;
            Id = id;
            Length = length;
            Status = status;
            _alternatives = alternatives;

            if (!deprecatedSince.HasValue)
            {
                _deprecatedSince = obsoleteSince;
            }
            else if (!obsoleteSince.HasValue)
            {
                _deprecatedSince = deprecatedSince;
            }
            else
            {
                _deprecatedSince = deprecatedSince > obsoleteSince ? obsoleteSince : deprecatedSince;
            }

            _obsoleteSince = obsoleteSince;
        }

        /// <summary>
        ///     Return Guardtime id of algorithm.
        /// </summary>
        public byte Id { get; }

        /// <summary>
        ///     Return name of algorithm.
        /// </summary>
        public string Name { get; }

        /// <summary>
        ///     Return length of the algorithm return value.
        /// </summary>
        public int Length { get; }

        /// <summary>
        ///     Return status of the algorithm.
        /// </summary>
        public AlgorithmStatus Status { get; }

        /// <summary>
        /// Returns true if the algorithm has deprecated since date set.
        /// </summary>
        public bool HasDeprecatedSinceDate => _deprecatedSince.HasValue;

        /// <summary>
        /// Returns deprecated since date. 
        /// </summary>
        public DateTime? DeprecatedSinceDate => _deprecatedSince.HasValue ? Util.ConvertUnixTimeToDateTime(_deprecatedSince.Value) : (DateTime?)null;

        /// <summary>
        /// Returns true if the algorithm is deprecated at the given date
        /// </summary>
        /// <returns></returns>
        public bool IsDeprecated(ulong date)
        {
            return (_deprecatedSince.HasValue && date >= _deprecatedSince.Value) || IsObsolete(date);
        }

        /// <summary>
        /// Returns obsolete since date.
        /// </summary>
        public DateTime? ObsoleteSinceDate => _obsoleteSince.HasValue ? Util.ConvertUnixTimeToDateTime(_obsoleteSince.Value) : (DateTime?)null;

        /// <summary>
        /// Returns true if the algorithm is obsolete at the given date
        /// </summary>
        /// <returns></returns>
        public bool IsObsolete(ulong date)
        {
            return _obsoleteSince.HasValue && date >= _obsoleteSince.Value;
        }

        /// <summary>
        ///     Get hash algorithm by id/code.
        /// </summary>
        /// <param name="id">one-byte hash function identifier</param>
        /// <returns>HashAlgorithm when a match is found, otherwise null</returns>
        public static HashAlgorithm GetById(byte id)
        {
            foreach (HashAlgorithm algorithm in Values)
            {
                if (algorithm.Id == id)
                {
                    return algorithm;
                }
            }

            if (IsInvalidAlgorithm(id))
            {
                throw new HashingException("Invalid hash algorithm. Id: " + id);
            }

            return null;
        }

        /// <summary>
        /// Returns true if algorithm with given id is marked as invalid.
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public static bool IsInvalidAlgorithm(byte id)
        {
            foreach (byte algorithmId in InvalidHashAlgorithmIds)
            {
                if (algorithmId == id)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        ///     Get hash algorithm by name.
        /// </summary>
        /// <param name="name">name of the algorithm to look for</param>
        /// <returns>HashAlgorithm when match is found, otherwise null</returns>
        public static HashAlgorithm GetByName(string name)
        {
            name = NameNormalize(name);
            return Lookup.ContainsKey(name) ? Lookup[name] : null;
        }

        /// <summary>
        ///     Get list of supported the algorithms.
        /// </summary>
        /// <returns>List of supported hash algorithm names</returns>
        public static IEnumerable<string> GetNamesList()
        {
            foreach (HashAlgorithm algorithm in Values)
            {
                yield return algorithm.Name;
            }
        }

        /// <summary>
        ///     Helper method to normalize the algorithm names for name search.
        /// </summary>
        /// <param name="name">algorithm name to normalize</param>
        /// <returns>name stripped of all non-alphanumeric characters</returns>
        private static string NameNormalize(string name)
        {
            return Regex.Replace(name.ToLower(), "[^a-z0-9]", "", RegexOptions.Compiled);
        }
    }
}