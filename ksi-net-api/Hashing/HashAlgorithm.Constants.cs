using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Hashing
{
    partial class HashAlgorithm
    {
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
    }
}