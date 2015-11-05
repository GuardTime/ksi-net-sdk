namespace Guardtime.KSI.Utils
{
    /// <summary>
    ///     Base16 (Hex) converter.
    /// </summary>
    public static class Base16
    {
        private static readonly BaseX Inst = new BaseX("0123456789ABCDEF", false, ' ');

        /// <summary>
        ///     Encode data bytes to hex string.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <returns>hex string</returns>
        public static string Encode(byte[] bytes)
        {
            return Encode(bytes, 0, bytes.Length);
        }

        /// <summary>
        ///     Encode data bytes with given offset and length to hex string.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <param name="off">data offset</param>
        /// <param name="len">data length</param>
        /// <returns>hex string</returns>
        public static string Encode(byte[] bytes, int off, int len)
        {
            return bytes == null ? null : Inst.Encode(bytes, off, len, null, 0);
        }

        /// <summary>
        ///     Decode hex string to byte array.
        /// </summary>
        /// <param name="s">hex string</param>
        /// <returns>hex bytes</returns>
        public static byte[] Decode(string s)
        {
            return s == null ? null : Inst.Decode(s);
        }
    }
}