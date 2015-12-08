﻿using System;
using System.Text;
using Guardtime.KSI.Exceptions;

namespace Guardtime.KSI.Utils
{
    /// <summary>
    ///     Utilities object.
    /// </summary>
    public static class Util
    {
        private static readonly Random Random = new Random();

        /// <summary>
        ///     Clone given byte array
        /// </summary>
        /// <param name="source">byte array to be cloned</param>
        /// <returns></returns>
        public static byte[] Clone(byte[] source)
        {
            byte[] bytes = new byte[source.Length];
            source.CopyTo(bytes, 0);
            return bytes;
        }

        /// <summary>
        ///     Clone part of byte array
        /// </summary>
        /// <param name="source">byte array to be cloned</param>
        /// <param name="startIndex">source array index to start cloning from</param>
        /// <param name="byteCount">amount of bytes to clone</param>
        /// <returns></returns>
        public static byte[] Clone(byte[] source, int startIndex, int byteCount)
        {
            byte[] bytes = new byte[byteCount];
            Array.Copy(source, startIndex, bytes, 0, byteCount);
            return bytes;
        }

        /// <summary>
        ///     Are given arrays equal with same data ordering.
        /// </summary>
        /// <typeparam name="T">any type</typeparam>
        /// <param name="arr1">first array</param>
        /// <param name="arr2">second array</param>
        /// <returns>true if arrays are equal</returns>
        public static bool IsArrayEqual<T>(T[] arr1, T[] arr2)
        {
            if (arr1 == null && arr2 == null)
            {
                return true;
            }

            // If only one is null
            if (arr1 == null ^ arr2 == null)
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
        ///     Decode byte array to unsigned long.
        /// </summary>
        /// <param name="buf">byte array</param>
        /// <param name="ofs">data offset</param>
        /// <param name="len">data length</param>
        /// <returns>unsigned long</returns>
        public static ulong DecodeUnsignedLong(byte[] buf, int ofs, int len)
        {
            if (buf == null)
            {
                throw new KsiException("Input byte array cannot be null.");
            }

            if (ofs < 0 || len < 0 || ofs + len < 0 || ofs + len > buf.Length)
            {
                throw new KsiException("Index out of bounds.");
            }
            if (len > 8)
            {
                throw new KsiException("Integers of at most 63 unsigned bits supported by this implementation.");
            }

            ulong t = 0;
            for (int i = 0; i < len; ++i)
            {
                t = (t << 8) | buf[ofs + i];
            }

            return t;
        }

        /// <summary>
        ///     Encode unsigned long to byte array.
        /// </summary>
        /// <param name="value">unsigned long</param>
        /// <returns>byte array</returns>
        public static byte[] EncodeUnsignedLong(ulong value)
        {
            int n = 0;

            for (ulong t = value; t > 0; t >>= 8)
            {
                ++n;
            }

            byte[] res = new byte[n];

            for (ulong t = value; t > 0; t >>= 8)
            {
                res[--n] = (byte)t;
            }

            return res;
        }

        /// <summary>
        ///     Convert DateTime to unix time.
        /// </summary>
        /// <param name="time">time in DateTime format</param>
        /// <returns>unix time</returns>
        public static ulong ConvertDateTimeToUnixTime(DateTime time)
        {
            TimeSpan timeSpan = time - new DateTime(1970, 1, 1, 0, 0, 0);
            return (ulong)timeSpan.TotalSeconds;
        }

        /// <summary>
        ///     Convert unix time to DateTime.
        /// </summary>
        /// <param name="time">unix time</param>
        /// <returns>time as DateTime</returns>
        public static DateTime ConvertUnixTimeToDateTime(ulong time)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0) + TimeSpan.FromSeconds(time);
        }

        /// <summary>
        ///     Decode null terminated UTF-8 string from bytes.
        /// </summary>
        /// <param name="bytes">string bytes</param>
        /// <returns>utf-8 string</returns>
        public static string DecodeNullTerminatedUtf8String(byte[] bytes)
        {
            if (bytes == null)
            {
                throw new KsiException("Input bytes cannot be null.");
            }

            if (bytes.Length == 0 || bytes[bytes.Length - 1] != 0)
            {
                throw new KsiException("String must be null terminated.");
            }

            return Encoding.UTF8.GetString(bytes, 0, bytes.Length - 1);
        }

        /// <summary>
        ///     Encode null terminated byte array to UTF-8 string.
        /// </summary>
        /// <param name="value">utf-8 string</param>
        /// <returns>byte array</returns>
        public static byte[] EncodeNullTerminatedUtf8String(string value)
        {
            if (value == null)
            {
                throw new KsiException("Input string cannot be null.");
            }

            byte[] stringBytes = Encoding.UTF8.GetBytes(value);
            byte[] bytes = new byte[stringBytes.Length + 1];
            Array.Copy(stringBytes, 0, bytes, 0, stringBytes.Length);
            return bytes;
        }

        /// <summary>
        ///     Get random unsigned long.
        /// </summary>
        /// <returns>random unsigned long</returns>
        public static ulong GetRandomUnsignedLong()
        {
            byte[] bytes = new byte[8];
            Random.NextBytes(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }

        /// <summary>
        ///     Fill array with specific value
        /// </summary>
        /// <param name="arr">array of values</param>
        /// <param name="value">value to write to array</param>
        /// <typeparam name="T">array type</typeparam>
        public static void ArrayFill<T>(T[] arr, T value)
        {
            if (arr == null)
            {
                throw new KsiException("Input array cannot be null.");
            }

            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = value;
            }
        }

        /// <summary>
        ///     Find the Greatest Common Divisor
        /// </summary>
        /// <param name="a">Number a</param>
        /// <param name="b">Number b</param>
        /// <returns>The greatest common Divisor</returns>
        public static int GetGreatestCommonDivisor(int a, int b)
        {
            while (b != 0)
            {
                int tmp = b;
                b = a % b;
                a = tmp;
            }

            return a;
        }

        /// <summary>
        ///     Find the Least Common Multiple
        /// </summary>
        /// <param name="a">Number a</param>
        /// <param name="b">Number b</param>
        /// <returns>The least common multiple</returns>
        public static int GetLeastCommonMultiple(int a, int b)
        {
            return (a * b) / GetGreatestCommonDivisor(a, b);
        }

        /// <summary>
        ///     Put tab prefix instead of new rows.
        /// </summary>
        /// <param name="s">string</param>
        /// <returns>tab prefixed string</returns>
        public static string TabPrefixString(string s)
        {
            StringBuilder builder = new StringBuilder();

            string[] lines = s.Split(new[] {Environment.NewLine}, StringSplitOptions.None);
            for (int i = 0; i < lines.Length; i++)
            {
                builder.Append("  ");
                builder.Append(lines[i]);
                if (!lines[i].Equals(lines[lines.Length - 1]))
                {
                    builder.AppendLine();
                }
            }

            return builder.ToString();
        }

        public static bool IsOneValueEqualTo<T>(T expectedValue, params T[] values)
        {
            int count = 0;
            foreach (T value in values)
            {
                if (expectedValue == null)
                {
                    if (value != null)
                    {
                        continue;
                    }
                }
                else if (!expectedValue.Equals(value))
                {
                    continue;
                }

                count++;

                if (count > 1)
                {
                    return false;
                }
            }

            return count == 1;
        }
    }
}