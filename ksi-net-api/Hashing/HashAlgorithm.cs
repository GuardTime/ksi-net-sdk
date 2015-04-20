using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// List of supported hash functions and also some convenience functions.
    /// </summary>
    public class HashAlgorithm
    {
        public static readonly HashAlgorithm Sha1 = new HashAlgorithm("SHA1", 0x0, 20, AlgorithmStatus.NotTrusted);
        public static readonly HashAlgorithm Sha2256 = new HashAlgorithm("SHA-256", 0x01, 32, AlgorithmStatus.Normal, new string[] { "SHA2-256", "SHA2", "DEFAULT" });
        public static readonly HashAlgorithm Ripemd160 = new HashAlgorithm("RIPEMD160", 0x02, 20, AlgorithmStatus.Normal);
        public static readonly HashAlgorithm Sha2224 = new HashAlgorithm("SHA-224", 0x03, 28, AlgorithmStatus.Normal, new string[] { "SHA2-224" });
        public static readonly HashAlgorithm Sha2384 = new HashAlgorithm("SHA-384", 0x04, 48, AlgorithmStatus.Normal, new string[] { "SHA2-384" });
        public static readonly HashAlgorithm Sha2512 = new HashAlgorithm("SHA-512", 0x05, 64, AlgorithmStatus.Normal, new string[] { "SHA2-512" });
        public static readonly HashAlgorithm Ripemd256 = new HashAlgorithm("RIPEMD256", 0x06, 32, AlgorithmStatus.NotImplemented);
        public static readonly HashAlgorithm Sha3224 = new HashAlgorithm("SHA3-224", 0x07, 28, AlgorithmStatus.NotImplemented);
        public static readonly HashAlgorithm Sha3256 = new HashAlgorithm("SHA3-256", 0x08, 32, AlgorithmStatus.NotImplemented);
        public static readonly HashAlgorithm Sha3384 = new HashAlgorithm("SHA3-384", 0x09, 48, AlgorithmStatus.NotImplemented);
        public static readonly HashAlgorithm Sha3512 = new HashAlgorithm("SHA3-512", 0x0A, 64, AlgorithmStatus.NotImplemented);
        public static readonly HashAlgorithm Sm3 = new HashAlgorithm("SM3", 0x0B, 32, AlgorithmStatus.NotImplemented);

        private readonly string _name;
        private readonly byte _id;
        private readonly int _length;
        private readonly AlgorithmStatus _status;
        private readonly string[] _alternatives;
        private static readonly Dictionary<string, HashAlgorithm> Lookup = new Dictionary<string, HashAlgorithm>();

        /// <summary>
        /// Return Guardtime id of algorithm.
        /// </summary>
        public byte Id
        {
            get { return _id; }
        }

        /// <summary>
        /// Return name of algorithm.
        /// </summary>
        public string Name
        {
            get { return _name; }
        }

        /// <summary>
        /// Return length of the algorithm value.
        /// </summary>
        public int Length
        {
            get { return _length; }
        }

        /// <summary>
        /// Return status of the algorithm.
        /// </summary>
        public AlgorithmStatus Status
        {
            get { return _status; }
        }

        /// <summary>
        /// Static constructor for creating lookup table for names.
        /// </summary>
        static HashAlgorithm()
        {
            foreach (var algorithm in Values())
            {
                Lookup.Add(NameNormalize(algorithm.Name), algorithm);
                foreach (var alternative in algorithm._alternatives)
                {
                    Lookup.Add(NameNormalize(alternative), algorithm);
                }
            }
        }

        /// <summary>
        /// Private constructor for HashAlgorithm object.
        /// </summary>
        /// <param name="name">algorithm name</param>
        /// <param name="id">algorithm Guardtime id</param>
        /// <param name="length">algorithm value length</param>
        /// <param name="status">algorithm status</param>
        /// <param name="alternatives">algorithm alternative names</param>
        private HashAlgorithm(string name, byte id, int length, AlgorithmStatus status, string[] alternatives = null)
        {
            if (alternatives == null)
            {
                alternatives = new string[] { };
            }

            this._name = name;
            this._id = id;
            this._length = length;
            this._status = status;
            this._alternatives = alternatives;
        }

        /// <summary>
        /// Get hash algorithm by id/code.
        /// </summary>
        /// <param name="id">one-byte hash function identifier</param>
        /// <returns>HashAlgorithm when a match is found, otherwise null</returns>
        public static HashAlgorithm GetById(byte id) 
        {

            foreach (var algorithm in Values()) {
                if (algorithm.Id == id) {
                    return algorithm;
                }
            }

            return null;
        }

        /// <summary>
        /// Get hash algorithm by name.
        /// </summary>
        /// <param name="name">name of the algorithm to look for</param>
        /// <returns>HashAlgorithm when match is found, otherwise null</returns>
        public static HashAlgorithm GetByName(string name)
        {
            name = NameNormalize(name);
            return Lookup.ContainsKey(name) ? Lookup[name] : null;
        }

        /// <summary>
        /// Get list of supported the algorithms.
        /// </summary>
        /// <returns>List of supported hash algorithm names</returns>
        public static List<string> GetNamesList() 
        {
            var names = new List<string>();
            foreach (var algorithm in Values()) {
                names.Add(algorithm.Name);
            }
            return names;
        }

        /// <summary>
        /// Helper method to normalize the algorithm names for name search.
        /// </summary>
        /// <param name="name">algorithm name to normalize</param>
        /// <returns>name stripped of all non-alphanumeric characters</returns>
        static string NameNormalize(string name)
        {
            return Regex.Replace(name.ToLower(), "[^a-zA-Z0-9]", "");
        }

        /// <summary>
        /// Get available algorithm objects.
        /// </summary>
        /// <returns>Defined HashAlgorithm objects</returns>
        private static IEnumerable<HashAlgorithm> Values()
        {
            return new HashAlgorithm[]
                {Sha1, Sha2256, Ripemd160, Sha2224, Sha2384, Sha2512, Ripemd256, Sha3224, Sha3256, Sha3384, Sha3512, Sm3};
        }

        /// <summary>
        /// HashAlgorithm Status enum.
        /// </summary>
        public enum AlgorithmStatus
        {

            /// <summary>
            /// Normal fully supported algorithm.
            /// </summary>
            Normal,
            /// <summary>
            /// Algorithm no longer considered secure and only kept for backwards 
            /// compatibility. Should not be used in new signatures. Should trigger
            /// verification warnings when encountered in existing signatures.
            /// </summary>
            NotTrusted,
            /// <summary>
            /// Algorithm defined in the specification, but not yet available in the implementation.
            /// </summary>
            NotImplemented
        }
    }


    
}
