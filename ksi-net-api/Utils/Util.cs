using System;
using System.Text;

namespace Guardtime.KSI.Utils
{
    /// <summary>
    /// Utilities object.
    /// </summary>
    public static class Util
    {
        private static readonly Random Random = new Random();

        /// <summary>
        /// Are given arrays equal with same data ordering.
        /// </summary>
        /// <typeparam name="T">any type</typeparam>
        /// <param name="arr1">first array</param>
        /// <param name="arr2">second array</param>
        /// <returns>true if arrays are equal</returns>
        public static bool IsArrayEqual<T>(T[] arr1, T[] arr2) 
        {
            if (arr1 == null || arr2 == null)
            {
                return false;
            }

            if (arr1.Length != arr2.Length)
            {
                return false;
            }

            for (int i = 0; i < arr1.Length; i++)
            {
                if (!Equals(arr1[i], arr2[i]))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Convert byte array to hex string.
        /// </summary>
        /// <param name="valueBytes">data bytes</param>
        /// <returns>hex string</returns>
        public static string ConvertByteArrayToHexString(byte[] valueBytes)
        {
            return valueBytes == null ? "" : BitConverter.ToString(valueBytes).Replace("-", string.Empty);
        }

        /// <summary>
        /// Decode byte array to unsigned long.
        /// </summary>
        /// <param name="buf">byte array</param>
        /// <param name="ofs">data offset</param>
        /// <param name="len">data length</param>
        /// <returns>unsigned long</returns>
        public static ulong DecodeUnsignedLong(byte[] buf, int ofs, int len) {
            if (buf == null)
            {
                throw new ArgumentNullException("buf");
            }

            if (ofs < 0 || len < 0 || ofs + len < 0 || ofs + len > buf.Length) {
                throw new IndexOutOfRangeException();
            }
            if (len > 8) {
                // TODO: better exception and handling
                throw new FormatException("Integers of at most 63 unsigned bits supported by this implementation");
            }
            
            ulong t = 0;
            for (int i = 0; i < len; ++i) {
                t = (t << 8) | ((ulong) buf[ofs + i] & 0xff);
            }

            return t;
        }

        /// <summary>
        /// Encode unsigned long to byte array.
        /// </summary>
        /// <param name="value">unsigned long</param>
        /// <returns>byte array</returns>
        public static byte[] EncodeUnsignedLong(ulong value) {
            int n = 0;

            for (ulong t = value; t > 0; t >>= 8) {
                ++n;
            }

            byte[] res = new byte[n];

            for (ulong t = value; t > 0; t >>= 8) {
                res[--n] = (byte) t;
            }

            return res;
        }

        /// <summary>
        /// Convert DateTime to unix time.
        /// </summary>
        /// <param name="time">time in DateTime format</param>
        /// <returns>unix time</returns>
        public static ulong ConvertDateTimeToUnixTime(DateTime time)
        {
            TimeSpan timeSpan = (time - new DateTime(1970, 1, 1, 0, 0, 0));
            return (ulong) timeSpan.TotalSeconds;
        }

        /// <summary>
        /// Convert unix time to DateTime.
        /// </summary>
        /// <param name="time">unix time</param>
        /// <returns>time as DateTime</returns>
        public static DateTime ConvertUnixTimeToDateTime(ulong time)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0) + TimeSpan.FromSeconds(time);
        }

        /// <summary>
        /// Decode null terminated UTF-8 string from bytes.
        /// </summary>
        /// <param name="bytes">string bytes</param>
        /// <returns>utf-8 string</returns>
        public static string DecodeNullTerminatedUtf8String(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new ArgumentNullException("bytes");
            }

            if (bytes.Length == 0 || bytes[bytes.Length - 1] != 0)
            {
                // TODO: Use correct exception
                throw new FormatException("String must be null terminated");
            }

            return Encoding.UTF8.GetString(bytes, 0, bytes.Length - 1);
        }

        /// <summary>
        /// Encode null terminated byte array to UTF-8 string.
        /// </summary>
        /// <param name="value">utf-8 string</param>
        /// <returns>byte array</returns>
        public static byte[] EncodeNullTerminatedUtf8String(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            byte[] stringBytes = Encoding.UTF8.GetBytes(value);
            byte[] bytes = new byte[stringBytes.Length + 1];
            Array.Copy(stringBytes, 0, bytes, 0, stringBytes.Length);
            return bytes;
        }

        /// <summary>
        /// Get random unsigned long.
        /// </summary>
        /// <returns>random unsigned long</returns>
        public static ulong GetRandomUnsignedLong()
        {
            byte[] bytes = new byte[8];
            Random.NextBytes(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

    }
}
