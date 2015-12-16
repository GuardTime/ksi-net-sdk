namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// HMAC hasher
    /// </summary>
    public interface IHmacHasher
    {
        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="key">HMAC key</param>
        /// <param name="data">HMAC calculation data</param>
        /// <returns>HMAC data hash</returns>
        DataHash GetHash(byte[] key, byte[] data);
    }
}