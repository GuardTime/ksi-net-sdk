using System;

namespace Guardtime.KSI.Util
{
    public class Util
    {
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

        
    }
}
