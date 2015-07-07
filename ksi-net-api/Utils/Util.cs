﻿using System;
using System.Text;

namespace Guardtime.KSI.Utils
{
    public static class Util
    {
        private static readonly Random Random = new Random();

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

        public static string ConvertByteArrayToString(byte[] valueBytes)
        {
            return valueBytes == null ? "" : BitConverter.ToString(valueBytes).Replace("-", string.Empty);
        }

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

        public static ulong ConvertDateTimeToUnixTime(DateTime time)
        {
            TimeSpan timeSpan = (time - new DateTime(1970, 1, 1, 0, 0, 0));
            return (ulong) timeSpan.TotalSeconds;
        }

        public static DateTime ConvertUnixTimeToDateTime(ulong time)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0) + TimeSpan.FromSeconds(time);
        }

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

        public static ulong GetRandomUnsignedLong()
        {
            byte[] bytes = new byte[32];
            Random.NextBytes(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

    }
}