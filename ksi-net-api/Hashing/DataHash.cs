using System;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// Representation of hash values as hash computation results.
    /// Includes name of the algorithm used and computed hash value.
    /// </summary>
    public class DataHash
    {
        /// <summary>
        /// Get the HashAlgorithm used to compute this DataHash.
        /// </summary>
        public HashAlgorithm Algorithm { get; }

        /// <summary>
        /// Get data imprint.
        /// <p>
        /// Imprint is created by concatenating hash algorithm id with hash value.
        /// </p>
        /// </summary>
        public byte[] Imprint { get; }

        /// <summary>
        /// Get the computed hash value for DataHash.
        /// </summary>
        public byte[] Value { get; }

        /// <summary>
        /// Constructor which initializes the DataHash with algorithm and value.
        /// </summary>
        /// <param name="algorithm">HashAlgorithm used to compute this hash.</param>
        /// <param name="valueBytes">hash value computed for the input data.</param>
        public DataHash(HashAlgorithm algorithm, byte[] valueBytes)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            if (valueBytes == null)
            {
                throw new ArgumentNullException(nameof(valueBytes));
            }

            if (valueBytes.Length != algorithm.Length)
            {
                throw new FormatException("Hash size(" + valueBytes.Length + ") does not match "
                            + algorithm.Name + " size(" + algorithm.Length + ")");
            }

            Algorithm = algorithm;
            Value = valueBytes;

            Imprint = new byte[Algorithm.Length + 1];
            Imprint[0] = Algorithm.Id;
            Array.Copy(Value, 0, Imprint, 1, Algorithm.Length);
        }

        /// <summary>
        /// Constructor which initializes the DataHash with imprint.
        /// </summary>
        /// <param name="imprintBytes">Hash imprint</param>
        public DataHash(byte[] imprintBytes)
        {
            if (imprintBytes == null)
            {
                throw new ArgumentNullException(nameof(imprintBytes));
            }

            if (imprintBytes.Length < 1)
            {
                throw new ArgumentException("Hash imprint too short");
            }

            Algorithm = HashAlgorithm.GetById(imprintBytes[0]);

            if (Algorithm == null)
            {
                throw new FormatException("Hash algorithm ID unknown: " + imprintBytes[0]);
            }

            if (Algorithm.Length + 1 != imprintBytes.Length)
            {
                throw new FormatException("Hash size(" + (imprintBytes.Length - 1) + ") does not match "
                           + Algorithm.Name + " size(" + Algorithm.Length + ")");
            }

            Value = new byte[Algorithm.Length];
            Array.Copy(imprintBytes, 1, Value, 0, Algorithm.Length);
            Imprint = imprintBytes;
        }

        /// <summary>
        /// Check if object is equal to current DataHash.
        /// </summary>
        /// <param name="obj">Object</param>
        /// <returns>boolean where true means that objects are equal</returns>
        public override bool Equals(object obj)
        {
            if (obj == null || obj.GetType() != typeof (DataHash)) return false;
            var b = (DataHash) obj;
            return Util.Util.IsArrayEqual(b.Imprint, Imprint) &&
                   Util.Util.IsArrayEqual(b.Value, Value) &&
                   b.Algorithm.Equals(Algorithm);
        }

        /// <summary>
        /// Get hash code of current object.
        /// </summary>
        /// <returns>hash code of current object</returns>
        public override int GetHashCode()
        {
            // TODO: Generate correct hashcode
            return 1;
        }

        /// <summary>
        /// Get DataHash as a string including the algorithm name and computed hash value.
        /// </summary>
        /// <returns>String representing algorithm name and value</returns>
        public override string ToString()
        {
            return Algorithm.Name + ":[" + Util.Util.ConvertByteArrayToHex(Value) + "]";
        }
    }
}
