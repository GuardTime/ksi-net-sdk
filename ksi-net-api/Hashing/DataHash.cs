using Guardtime.KSI.Utils;
using System;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// Representation of hash values as hash computation results.
    /// Includes name of the algorithm used and computed hash value.
    /// </summary>
    public class DataHash : IEquatable<DataHash>
    {
        private readonly HashAlgorithm _algorithm;
        private readonly byte[] _imprint;
        private readonly byte[] _value;

        /// <summary>
        /// Get the HashAlgorithm used to compute this DataHash.
        /// </summary>
        public HashAlgorithm Algorithm
        {
            get { return _algorithm; }
        }

        /// <summary>
        /// Get data imprint.
        /// Imprint is created by concatenating hash algorithm id with hash value.
        /// </summary>
        public byte[] Imprint
        {
            // TODO: Fix the clone with immutable array
            get { return (byte[])_imprint.Clone(); }
        }

        /// <summary>
        /// Get the computed hash value for DataHash.
        /// </summary>
        public byte[] Value {
            // TODO: Fix the clone with immutable array
            get { return (byte[])_value.Clone(); }
        }

        /// <summary>
        /// Constructor which initializes the DataHash with algorithm and value.
        /// </summary>
        /// <param name="algorithm">HashAlgorithm used to compute this hash.</param>
        /// <param name="valueBytes">hash value computed for the input data.</param>
        public DataHash(HashAlgorithm algorithm, byte[] valueBytes)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            if (valueBytes == null)
            {
                throw new ArgumentNullException("valueBytes");
            }

            if (valueBytes.Length != algorithm.Length)
            {
                // TODO: Better exception here
                throw new FormatException("Hash size(" + valueBytes.Length + ") does not match "
                            + algorithm.Name + " size(" + algorithm.Length + ")");
            }

            _algorithm = algorithm;
            _value = valueBytes;

            _imprint = new byte[Algorithm.Length + 1];
            _imprint[0] = Algorithm.Id;
            Array.Copy(_value, 0, _imprint, 1, Algorithm.Length);
        }

        /// <summary>
        /// Constructor which initializes the DataHash with imprint.
        /// </summary>
        /// <param name="imprintBytes">Hash imprint</param>
        public DataHash(byte[] imprintBytes)
        {
            if (imprintBytes == null)
            {
                throw new ArgumentNullException("imprintBytes");
            }

            if (imprintBytes.Length == 0)
            {
                throw new ArgumentException("Hash imprint too short", "imprintBytes");
            }

            _algorithm = HashAlgorithm.GetById(imprintBytes[0]);

            if (_algorithm == null)
            {
                // TODO: Better exception
                throw new FormatException("Hash algorithm ID unknown: " + imprintBytes[0]);
            }

            if (_algorithm.Length + 1 != imprintBytes.Length)
            {
                // TODO: Better exception
                throw new FormatException("Hash size(" + (imprintBytes.Length - 1) + ") does not match "
                           + _algorithm.Name + " size(" + _algorithm.Length + ")");
            }

            _value = new byte[_algorithm.Length];
            Array.Copy(imprintBytes, 1, _value, 0, _algorithm.Length);
            _imprint = imprintBytes;
        }

        /// <summary>
        /// Compare TLV element to object.
        /// </summary>
        /// <param name="obj">Comparable object.</param>
        /// <returns>true if objects are equal</returns>
        public override bool Equals(object obj)
        {
            return Equals(obj as DataHash);
        }

        /// <summary>
        /// Compare current hash against another hash.
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

            // If run-time types are not exactly the same, return false. 
            if (GetType() != hash.GetType())
            {
                return false;
            }

            return Util.IsArrayEqual(_imprint, hash._imprint);
        }

        /// <summary>
        /// Get hash code of current object.
        /// </summary>
        /// <returns>hash code of current object</returns>
        public override int GetHashCode()
        {
            unchecked
            {
                int res = 1;
                for (int i = 0; i < _imprint.Length; i++)
                {
                    res = 31 * res + _imprint[i];
                }

                return res;
            }
        }

        /// <summary>
        /// Get DataHash as a string including the algorithm name and computed hash value.
        /// </summary>
        /// <returns>String representing algorithm name and value</returns>
        public override string ToString()
        {
            return Algorithm.Name + ":[" + Util.ConvertByteArrayToHexString(_value) + "]";
        }

        /// <summary>
        /// Compares two hash objects.
        /// </summary>
        /// <param name="a">hash</param>
        /// <param name="b">hash</param>
        /// <returns>true if hashes are equal</returns>
        public static bool operator ==(DataHash a, DataHash b)
        {
            return ReferenceEquals(a, null) ? ReferenceEquals(b, null) : a.Equals(b);
        }

        /// <summary>
        /// Compares two hash objects for non equality.
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
