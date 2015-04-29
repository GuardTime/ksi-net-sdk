using System;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// Representation of hash values as hash computation results.
    /// Includes name of the algorithm used and computed hash value.
    /// </summary>
    public class DataHash
    {
        private readonly HashAlgorithm _algorithm;
        private readonly byte[] _valueBytes;
        private readonly byte[] _imprintBytes;

        /// <summary>
        /// Get the HashAlgorithm used to compute this DataHash.
        /// </summary>
        public HashAlgorithm Algorithm
        {
            get { return _algorithm;  }
        }

        /// <summary>
        /// Get data imprint.
        /// <p>
        /// Imprint is created by concatenating hash algorithm id with hash value.
        /// </summary>
        public byte[] Imprint
        {
            get { return _imprintBytes; }
        }

        /// <summary>
        /// Get the computed hash value for DataHash.
        /// </summary>
        public byte[] Value
        {
            get { return _valueBytes;  }
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
                throw new ArgumentNullException("Algorithm missing");
            }

            if (valueBytes == null)
            {
                throw new ArgumentNullException("Hash value missing");
            }

            if (valueBytes.Length != algorithm.Length)
            {
                throw new FormatException("Hash size(" + valueBytes.Length + ") does not match "
                            + algorithm.Name + " size(" + algorithm.Length + ")");
            }

            _algorithm = algorithm;
            _valueBytes = valueBytes;

            _imprintBytes = new byte[_algorithm.Length + 1];
            _imprintBytes[0] = (byte) _algorithm.Id;
            Array.Copy(_valueBytes, 0, _imprintBytes, 1, _algorithm.Length);
        }

        /// <summary>
        /// Constructor which initializes the DataHash with imprint.
        /// </summary>
        /// <param name="imprintBytes">Hash imprint</param>
        public DataHash(byte[] imprintBytes)
        {
            if (imprintBytes == null)
            {
                throw new ArgumentNullException("Hash imprint null");
            }

            if (imprintBytes.Length < 1)
            {
                throw new ArgumentException("Hash imprint too short");
            }

            _algorithm = HashAlgorithm.GetById(imprintBytes[0]);

            if (_algorithm == null)
            {
                throw new FormatException("Hash algorithm ID unknown: " + imprintBytes[0]);
            }

            if (_algorithm.Length + 1 != imprintBytes.Length)
            {
                throw new FormatException("Hash size(" + (imprintBytes.Length - 1) + ") does not match "
                           + _algorithm.Name + " size(" + _algorithm.Length + ")");
            }

            _valueBytes = new byte[_algorithm.Length];
            Array.Copy(imprintBytes, 1, _valueBytes, 0, _algorithm.Length);
            _imprintBytes = imprintBytes;
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
            return Util.Util.IsArrayEqual(b._imprintBytes, _imprintBytes) &&
                   Util.Util.IsArrayEqual(b._valueBytes, _valueBytes) &&
                   b._algorithm.Equals(_algorithm);
        }

        /// <summary>
        /// Get hash code of current object.
        /// </summary>
        /// <returns>hash code of current object</returns>
        public override int GetHashCode()
        {
            // TODO: Generate correct hashcode
            return base.GetHashCode();
        }

        /// <summary>
        /// Get DataHash as a string including the algorithm name and computed hash value.
        /// </summary>
        /// <returns>String representing algorithm name and value</returns>
        public override string ToString()
        {
            return _algorithm.Name + ":[" + Util.Util.ConvertByteArrayToHex(_valueBytes) + "]";
        }
    }
}
