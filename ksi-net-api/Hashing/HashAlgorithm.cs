using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Guardtime.KSI.Hashing
{
    /// <summary>
    ///     List of supported hash functions and also some convenience functions.
    /// </summary>
    public sealed class HashAlgorithm
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

        /// <summary>
        ///     SHA1 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha1 = new HashAlgorithm("SHA1", 0x0, 20, AlgorithmStatus.NotTrusted);

        /// <summary>
        ///     SHA2-256 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha2256 = new HashAlgorithm("SHA-256", 0x01, 32, AlgorithmStatus.Normal,
            new string[] {"SHA2-256", "SHA2", "DEFAULT"});

        /// <summary>
        ///     RIPEMD-160 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Ripemd160 = new HashAlgorithm("RIPEMD160", 0x02, 20, AlgorithmStatus.Normal);

        /// <summary>
        ///     SHA2-224 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha2224 = new HashAlgorithm("SHA-224", 0x03, 28, AlgorithmStatus.Normal,
            new string[] {"SHA2-224"});

        /// <summary>
        ///     SHA2-384 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha2384 = new HashAlgorithm("SHA-384", 0x04, 48, AlgorithmStatus.Normal,
            new string[] {"SHA2-384"});

        /// <summary>
        ///     SHA2-512 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha2512 = new HashAlgorithm("SHA-512", 0x05, 64, AlgorithmStatus.Normal,
            new string[] {"SHA2-512"});

        /// <summary>
        ///     SHA3-224 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3224 = new HashAlgorithm("SHA3-224", 0x07, 28,
            AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SHA3-256 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3256 = new HashAlgorithm("SHA3-256", 0x08, 32,
            AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SHA3-384 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3384 = new HashAlgorithm("SHA3-384", 0x09, 48,
            AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SHA3-512 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sha3512 = new HashAlgorithm("SHA3-512", 0x0A, 64,
            AlgorithmStatus.NotImplemented);

        /// <summary>
        ///     SM3 Hash Algorithm
        /// </summary>
        public static readonly HashAlgorithm Sm3 = new HashAlgorithm("SM3", 0x0B, 32, AlgorithmStatus.NotImplemented);

        private static readonly Dictionary<string, HashAlgorithm> Lookup = new Dictionary<string, HashAlgorithm>();

        private readonly string[] _alternatives;

        private readonly byte _id;
        private readonly int _length;
        private readonly string _name;
        private readonly AlgorithmStatus _status;

        /// <summary>
        ///     Static constructor for creating lookup table for names.
        /// </summary>
        static HashAlgorithm()
        {
            foreach (HashAlgorithm algorithm in Values())
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
        private HashAlgorithm(string name, byte id, int length, AlgorithmStatus status)
            : this(name, id, length, status, null)
        {
        }

        /// <summary>
        ///     Private constructor for HashAlgorithm object.
        /// </summary>
        /// <param name="name">algorithm name</param>
        /// <param name="id">algorithm Guardtime id</param>
        /// <param name="length">algorithm value length</param>
        /// <param name="status">algorithm status</param>
        /// <param name="alternatives">algorithm alternative names</param>
        private HashAlgorithm(string name, byte id, int length, AlgorithmStatus status, string[] alternatives)
        {
            if (alternatives == null)
            {
                alternatives = new string[] {};
            }

            _name = name;
            _id = id;
            _length = length;
            _status = status;
            _alternatives = alternatives;
        }


        /// <summary>
        ///     Return Guardtime id of algorithm.
        /// </summary>
        public byte Id
        {
            get { return _id; }
        }

        /// <summary>
        ///     Return name of algorithm.
        /// </summary>
        public string Name
        {
            get { return _name; }
        }

        /// <summary>
        ///     Return length of the algorithm value.
        /// </summary>
        public int Length
        {
            get { return _length; }
        }

        /// <summary>
        ///     Return status of the algorithm.
        /// </summary>
        public AlgorithmStatus Status
        {
            get { return _status; }
        }

        /// <summary>
        ///     Get hash algorithm by id/code.
        /// </summary>
        /// <param name="id">one-byte hash function identifier</param>
        /// <returns>HashAlgorithm when a match is found, otherwise null</returns>
        public static HashAlgorithm GetById(byte id)
        {
            foreach (HashAlgorithm algorithm in Values())
            {
                if (algorithm.Id == id)
                {
                    return algorithm;
                }
            }

            return null;
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
        public static IList<string> GetNamesList()
        {
            IList<string> names = new List<string>();
            foreach (HashAlgorithm algorithm in Values())
            {
                names.Add(algorithm.Name);
            }
            return names;
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

        /// <summary>
        ///     Get available algorithm objects.
        /// </summary>
        /// <returns>Defined HashAlgorithm objects</returns>
        private static IEnumerable<HashAlgorithm> Values()
        {
            return new HashAlgorithm[]
            {Sha1, Sha2256, Ripemd160, Sha2224, Sha2384, Sha2512, Sha3224, Sha3256, Sha3384, Sha3512, Sm3};
        }
    }
}