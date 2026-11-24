// What runtimes/aspnet-anticsrf.pfc rests on, asked of the real thing.
//
// The Idunno.AntiCsrf module writes its hidden field with
// new ObjectStateFormatter().Serialize(guid) and reads it back with
// Deserialize, with no signature. The policy lets through a field whose value
// opens "/wEF" and resets every other. That is right only if, on Microsoft's
// .NET Framework:
//
//   1. a serialized GUID string opens "/wEF" (ff 01, then 05 for a string);
//   2. no other kind of value does;
//   3. what follows a string is not read, and a value is not accepted with
//      its opening bytes altered.
//
// CI compiles this with the Framework's own csc on a Windows runner and fails
// if any of the three is false. Mono's formatter numbers its types
// differently, so it could not answer this.
using System;
using System.Collections;
using System.Web.UI;

public class TokenLayout {
  static int failures = 0;

  static void Check(bool ok, string what) {
    Console.WriteLine((ok ? "ok    " : "FAIL  ") + what);
    if (!ok) failures++;
  }

  static string Ser(object o) { return new ObjectStateFormatter().Serialize(o); }

  static string Back(string s) {
    try { object o = new ObjectStateFormatter().Deserialize(s); return o == null ? "null" : o.GetType().Name; }
    catch (Exception e) { return "throws " + e.GetType().Name; }
  }

  public static int Main() {
    Console.WriteLine(Environment.Version + " on " + Environment.OSVersion);

    string guid = Guid.NewGuid().ToString("D", System.Globalization.CultureInfo.InvariantCulture);
    string legit = Ser(guid);
    byte[] raw = Convert.FromBase64String(legit);
    Console.WriteLine("a GUID string serializes to " + legit + "  (" + legit.Length + " characters, bytes " + BitConverter.ToString(raw, 0, 4) + " ...)");
    Check(legit.StartsWith("/wEF", StringComparison.Ordinal), "a serialized GUID string opens /wEF");
    Check(raw[0] == 0xff && raw[1] == 0x01 && raw[2] == 0x05 && raw[3] == 0x24, "its bytes are ff 01 05 24: the marker, a string, 36 characters");
    for (int i = 0; i < 200; i++) {
      string other = Ser(Guid.NewGuid().ToString("D"));
      if (!other.StartsWith("/wEFJ", StringComparison.Ordinal)) { Check(false, "every GUID string opens /wEFJ: " + other); break; }
    }

    Console.WriteLine();
    object[][] others = new object[][] {
      new object[] { "an int", 7 }, new object[] { "zero", 0 }, new object[] { "a bool", true }, new object[] { "null", null }, new object[] { "an empty string", "" },
      new object[] { "a Pair", new Pair("a", "b") }, new object[] { "a Triplet", new Triplet("a", "b", "c") }, new object[] { "an object[]", new object[] { "a", 1 } },
      new object[] { "a string[]", new string[] { "a", "b" } }, new object[] { "an ArrayList", new ArrayList { "a" } }, new object[] { "a Hashtable", new Hashtable { { "a", "b" } } },
      new object[] { "a Type", typeof(string) }, new object[] { "a DateTime", DateTime.UtcNow }, new object[] { "a Unit", new System.Web.UI.WebControls.Unit(3) },
      new object[] { "a Version (binary-serialized)", new Version(1, 2) }, new object[] { "a Guid (binary-serialized)", Guid.NewGuid() },
    };
    foreach (object[] o in others) {
      string s = Ser(o[1]);
      byte[] b = Convert.FromBase64String(s);
      string open = s.Length >= 4 ? s.Substring(0, 4) : s;
      Console.WriteLine("      " + ((string)o[0]).PadRight(32) + " opens " + open.PadRight(5) + " type byte " + (b.Length > 2 ? b[2].ToString("x2") : "--"));
      Check(!s.StartsWith("/wEF", StringComparison.Ordinal), o[0] + " does not open /wEF");
    }

    Console.WriteLine();
    // a string followed by the bytes of something else: is the rest read?
    byte[] tail = Convert.FromBase64String(Ser(new Version(1, 2)));
    byte[] joined = new byte[raw.Length + tail.Length - 2];
    raw.CopyTo(joined, 0);
    Array.Copy(tail, 2, joined, raw.Length, tail.Length - 2);
    string appended = Back(Convert.ToBase64String(joined));
    Console.WriteLine("      a string with a serialized object appended -> " + appended);
    Check(appended == "String", "what follows a string is not read");

    string[][] forms = new string[][] {
      new string[] { "leading space", " " + legit }, new string[] { "leading newline", "\n" + legit }, new string[] { "a space inside the opening", legit.Substring(0, 2) + " " + legit.Substring(2) },
      new string[] { "lower-cased", legit.ToLowerInvariant() }, new string[] { "two values joined by a comma", legit + "," + legit }, new string[] { "base64url alphabet", legit.Replace('/', '_').Replace('+', '-') },
      new string[] { "empty", "" },
    };
    foreach (string[] f in forms) Console.WriteLine("      " + f[0].PadRight(32) + " -> " + Back(f[1]));
    // The policy resets a value that opens with whitespace because the
    // decoder skips it. If it does not, that reset is merely unnecessary.
    Console.WriteLine("      (whitespace before or inside the opening is reset by the policy either way)");

    Console.WriteLine();
    Console.WriteLine(failures == 0 ? "the policy's premise holds on this runtime" : failures + " of the policy's premises do not hold: runtimes/aspnet-anticsrf.pfc needs changing");
    return failures == 0 ? 0 : 1;
  }
}
