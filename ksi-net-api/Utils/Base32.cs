namespace Guardtime.KSI.Utils
{
    /// <summary>
    /// Base32 converter.
    /// </summary>
    public static class Base32
    {

        private static BaseX Inst = new BaseX("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", false, '=');

        /// <summary>
        /// Encode data bytes to base32 string.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <returns>base32 string</returns>
        public static string Encode(byte[] bytes)
        {
            return Encode(bytes, 0, bytes.Length);
        }

        /// <summary>
        /// Encode data bytes with given offset and length to base32 string.
        /// </summary>
        /// <param name="bytes">data bytes</param>
        /// <param name="off">data offset</param>
        /// <param name="len">data length</param>
        /// <returns>base32 string</returns>
        public static string Encode(byte[] bytes, int off, int len)
        {
            return bytes == null ? null : Inst.Encode(bytes, off, len, null, 0);
        }

        /// <summary>
        /// Decode base32 string to byte array.
        /// </summary>
        /// <param name="s">base32 string</param>
        /// <returns>base32 bytes</returns>
        public static byte[] Decode(string s)
        {
            return s == null ? null : Inst.Decode(s);
        }
    }
}