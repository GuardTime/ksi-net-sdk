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
using System;
using Guardtime.KSI.Exceptions;
using Guardtime.KSI.Utils;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    ///     Representation of hash values as hash computation results.
    ///     Includes name of the algorithm used and computed hash value.
    /// </summary>
    public class DataHash : IEquatable<DataHash>
    {
        private readonly byte[] _imprint;
        private readonly byte[] _value;

        /// <summary>
        ///     Constructor which initializes the DataHash with algorithm and value.
        /// </summary>
        /// <param name="algorithm">[NotNull] HashAlgorithm used to compute this hash.</param>
        /// <param name="valueBytes">[NotNull] hash value computed for the input data.</param>
        public DataHash(HashAlgorithm algorithm, byte[] valueBytes)
        {
            if (algorithm == null)
            {
                throw new HashingException("Invalid hash algorithm: null.");
            }

            if (valueBytes == null)
            {
                throw new HashingException("Invalid value bytes: null.");
            }

            if (valueBytes.Length != algorithm.Length)
            {
                throw new HashingException("Hash size(" + valueBytes.Length + ") does not match "
                                           + algorithm.Name + " size(" + algorithm.Length + ").");
            }

            Algorithm = algorithm;
            _value = valueBytes;

            _imprint = new byte[Algorithm.Length + 1];
            _imprint[0] = Algorithm.Id;
            Array.Copy(_value, 0, _imprint, 1, Algorithm.Length);
        }

        /// <summary>
        ///     Constructor which initializes the DataHash with imprint.
        /// </summary>
        /// <param name="imprintBytes">[NotNull] Hash imprint</param>
        public DataHash(byte[] imprintBytes)
        {
            if (imprintBytes == null)
            {
                throw new HashingException("Invalid hash imprint: null.");
            }

            if (imprintBytes.Length == 0)
            {
                throw new HashingException("Hash imprint is too short.");
            }

            Algorithm = HashAlgorithm.GetById(imprintBytes[0]);

            if (Algorithm == null)
            {
                throw new HashingException("Hash algorithm id(" + imprintBytes[0] + ") is unknown.");
            }

            if (Algorithm.Length + 1 != imprintBytes.Length)
            {
                throw new HashingException("Hash size(" + (imprintBytes.Length - 1) + ") does not match "
                                           + Algorithm.Name + " size(" + Algorithm.Length + ").");
            }

            _value = new byte[Algorithm.Length];
            Array.Copy(imprintBytes, 1, _value, 0, Algorithm.Length);
            _imprint = imprintBytes;
        }

        /// <summary>
        ///     Get the HashAlgorithm used to compute this DataHash.
        /// </summary>
        public HashAlgorithm Algorithm { get; }

        /// <summary>
        ///     Get data imprint.
        ///     Imprint is created by concatenating hash algorithm id with hash value.
        /// </summary>
        public byte[] Imprint => Util.Clone(_imprint);

        /// <summary>
        ///     Get the computed hash value for DataHash.
        /// </summary>
        public byte[] Value => Util.Clone(_value);

        /// <summary>
        ///     Compare current hash against another hash.
        /// </summary>
        /// <param name="hash">data hash</param>
        /// <returns>true if objects are equal</returns>
        public bool Equals(DataHash hash)
        {
            // If parameter is null, return false. 
            if (ReferenceEquals(hash, null))
            {
                return false;
            }

            if (ReferenceEquals(this, hash))
            {
                return true;
            }

            return GetType() == hash.GetType() && Util.IsArrayEqual(_imprint, hash._imprint);
        }

        /// <summary>
        ///     Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object.</param>
        /// <returns>true if objects are equal</returns>
        public override bool Equals(object obj)
        {
            return Equals(obj as DataHash);
        }

        /// <summary>
        ///     Get hash code of current object.
        /// </summary>
        /// <returns>hash code of current object</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                int res = 1;

                foreach (byte value in _imprint)
                {
                    res = 31 * res + value;
                }

                return res;
            }
        }

        /// <summary>
        ///     Get DataHash as a string including the algorithm name and computed hash value.
        /// </summary>
        /// <returns>String representing algorithm name and value</returns>
        public override string ToString()
        {
            return Algorithm.Name + ":[" + Base16.Encode(_value) + "]";
        }

        /// <summary>
        ///     Compares two hash objects.
        /// </summary>
        /// <param name="a">hash</param>
        /// <param name="b">hash</param>
        /// <returns>true if hashes are equal</returns>
        public static bool operator ==(DataHash a, DataHash b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        ///     Compares two hash objects for non equality.
        /// </summary>
        /// <param name="a">hash</param>
        /// <param name="b">hash</param>
        /// <returns>true if hashes are not equal</returns>
        public static bool operator !=(DataHash a, DataHash b)
        {
            return !(a == b);
        }
    }
}