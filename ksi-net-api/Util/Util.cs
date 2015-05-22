using System;
using System.Collections.Generic;
using System.Text;

namespace Guardtime.KSI.Util
{
    public class Util
    {
        private static Random _random = new Random();

        private Util()
        {
            
        }

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

            for (var i = 0; i < arr1.Length; i++)
            {
                if (!Equals(arr1[i], arr2[i]))
                {
                    return false;
                }
            }

            return true;
        }

        public static string ConvertByteArrayToHex(byte[] valueBytes)
        {
            return BitConverter.ToString(valueBytes).Replace("-", string.Empty);

        }

        public static ulong DecodeUnsignedLong(byte[] buf, int ofs, int len) {
            if (ofs < 0 || len < 0 || ofs + len < 0 || ofs + len > buf.Length) {
                throw new IndexOutOfRangeException();
            }
            if (len > 8) {
                // TODO: Catch exception
                throw new FormatException("Integers of at most 63 unsigned bits supported by this implementation");
            }
            
            ulong t = 0;
            for (var i = 0; i < len; ++i) {
                t = (t << 8) | ((ulong) buf[ofs + i] & 0xff);
            }

            return t;
        }


        public static byte[] EncodeUnsignedLong(ulong value) {
            var n = 0;

            for (var t = value; t > 0; t >>= 8) {
                ++n;
            }

            var res = new byte[n];

            for (var t = value; t > 0; t >>= 8) {
                res[--n] = (byte) t;
            }

            return res;
        }

        public static ulong ConvertDateTimeToUnixTime(DateTime time)
        {
            var timeSpan = (time - new DateTime(1970, 1, 1, 0, 0, 0));
            return (ulong) timeSpan.TotalSeconds;
        }

        public static DateTime ConvertUnixTimeToDateTime(ulong time)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0) + TimeSpan.FromSeconds(time);
        }

        public static string DecodeNullTerminatedUtf8String(byte[] bytes)
        {
            if (bytes.Length == 0 || bytes[bytes.Length - 1] != 0)
            {
                // TODO: Use correct exception
                throw new FormatException("String must be null terminated");
            }

            return Encoding.UTF8.GetString(bytes, 0, bytes.Length - 1);
        }

        public static byte[] EncodeNullTerminatedUtf8String(string value)
        {
            var stringBytes = Encoding.UTF8.GetBytes(value);
            var bytes = new byte[stringBytes.Length + 1];
            Array.Copy(stringBytes, 0, bytes, 0, stringBytes.Length);
            return bytes;
        }

        public static ulong GetRandomUnsignedLong()
        {
            var bytes = new byte[32];
            _random.NextBytes(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

    }
}
