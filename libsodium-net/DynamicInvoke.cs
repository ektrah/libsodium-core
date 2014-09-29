using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace Sodium
{
  internal static class DynamicInvoke
  {
    private static readonly Dictionary<string, Delegate> _cache = new Dictionary<string, Delegate>();

    public static T GetDynamicInvoke<T>(string function, string library)
    {
      var key = string.Format("{0}@{1}", function, library);

      if (!_cache.ContainsKey(key))
      {
        _cache.Add(key, (Delegate)(object)_CreateDynamicDllInvoke<T>(function, library));
      }

      return (T)(object)_cache[key];
    }

    //shamelessly copied from https://stackoverflow.com/a/1660807/230543
    private static T _CreateDynamicDllInvoke<T>(string functionName, string library)
    {
      // create in-memory assembly, module and type
      var assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(
          new AssemblyName("DynamicDllInvoke"),
          AssemblyBuilderAccess.Run);

      var modBuilder = assemblyBuilder.DefineDynamicModule("DynamicDllModule");

      // note: without TypeBuilder, you can create global functions
      // on the module level, but you cannot create delegates to them
      var typeBuilder = modBuilder.DefineType(
          "DynamicDllInvokeType",
          TypeAttributes.Public | TypeAttributes.UnicodeClass);

      // get params from delegate dynamically (!), trick from Eric Lippert
      var delegateMi = typeof(T).GetMethod("Invoke");
      var delegateParams = (from param in delegateMi.GetParameters()
                               select param.ParameterType).ToArray();

      // automatically create the correct signagure for PInvoke
      var methodBuilder = typeBuilder.DefinePInvokeMethod(
          functionName,
          library,
          MethodAttributes.Public |
          MethodAttributes.Static |
          MethodAttributes.PinvokeImpl,
          CallingConventions.Standard,
          delegateMi.ReturnType,        /* the return type */
          delegateParams,               /* array of parameters from delegate T */
          CallingConvention.Cdecl,
          CharSet.Ansi);

      // needed according to MSDN
      methodBuilder.SetImplementationFlags(methodBuilder.GetMethodImplementationFlags() | MethodImplAttributes.PreserveSig);

      var dynamicType = typeBuilder.CreateType();

      var methodInfo = dynamicType.GetMethod(functionName);

      // create the delegate of type T, double casting is necessary
      return (T)(object)Delegate.CreateDelegate(typeof(T), methodInfo, true);
    }
  }
}
