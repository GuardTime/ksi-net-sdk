namespace Guardtime.KSI.Hashing
{
    /// <summary>
    /// Hmac hasher
    /// </summary>
    public interface IHmacHasher
    {
        /// <summary>
        ///     Calculate HMAC for data with given key.
        /// </summary>
        /// <param name="key">hmac key</param>
        /// <param name="data">hmac calculation data</param>
        /// <returns>hmac data hash</returns>
        DataHash GetHash(byte[] key, byte[] data);
    }
}