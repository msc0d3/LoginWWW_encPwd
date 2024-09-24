using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace LoginWWWRequest.CryptoBranch.LibsodiumBranch.InteropBranch
{
    public class Core
    {
        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_init();

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_set_misuse_handler(
            Action handler);
    }
}
