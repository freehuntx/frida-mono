// Managed code the e2e tests poke at. Keep it C# 3 compatible: the oldest runtimes in the matrix ship old compilers.
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;

namespace FridaMono.Tests
{
    public static class Smoke
    {
        public static int Answer()
        {
            return 42;
        }
    }

    public enum Color
    {
        Red,
        Green = 5,
        Blue
    }

    [Flags]
    public enum Access : byte
    {
        None = 0,
        Read = 1,
        Write = 2
    }

    public interface IGreeter
    {
        string Greet(string name);
    }

    public struct Point
    {
        public int X;
        public int Y;

        public Point(int x, int y)
        {
            X = x;
            Y = y;
        }

        public int LengthSquared
        {
            get { return X * X + Y * Y; }
        }
    }

    public class Animal
    {
        public const int MaxLegs = 4;
        public static int Count;
        protected string name;
        public readonly int Legs;

        public Animal(string name) : this(name, 4)
        {
        }

        public Animal(string name, int legs)
        {
            this.name = name;
            Legs = legs;
            Count++;
        }

        public string Name
        {
            get { return name; }
            set { name = value; }
        }

        public int Age { get; private set; }

        public int this[int index]
        {
            get { return index * Legs; }
        }

        public event EventHandler Renamed;

        public static Animal Create(string name)
        {
            return new Animal(name);
        }

        public virtual string Speak()
        {
            return "...";
        }

        internal void OnRenamed()
        {
            if (Renamed != null) Renamed(this, EventArgs.Empty);
        }
    }

    public sealed class Dog : Animal, IGreeter
    {
        public Dog(string name) : base(name)
        {
        }

        public override string Speak()
        {
            return "Woof";
        }

        public string Greet(string other)
        {
            return "Hi " + other;
        }

        public class Collar
        {
            public string Tag;
        }
    }

    public abstract class Shape
    {
        public abstract double Area();
    }

    public static class Overloads
    {
        public static string Pick(Animal a) { return "Animal"; }
        public static string Pick(Dog d) { return "Dog"; }
        public static string Pick(bool b, bool c) { return "bool,bool"; }
        public static string Pick(int x) { return "int"; }
        public static string Pick(double x) { return "double"; }
        public static string Pick(string x) { return "string"; }
        public static string Pick(int x, int y) { return "int,int"; }

        public static bool TryDouble(int x, out int result)
        {
            result = x * 2;
            return true;
        }

        public static void Swap(ref int a, ref int b)
        {
            int t = a;
            a = b;
            b = t;
        }
    }

    public class Box<T>
    {
        public T Value;

        public Box(T value)
        {
            Value = value;
        }

        public T Get()
        {
            return Value;
        }

        public U Map<U>(Func<T, U> f)
        {
            return f(Value);
        }
    }

    public static class Generics
    {
        public static T Echo<T>(T value) { return value; }
        public static T[] Empty<T>() { return new T[0]; }
        public static int CountOf<T>(List<T> list) { return list.Count; }
        public static string NameOf<T>() { return typeof(T).FullName; }
    }

    public class Holder
    {
        public List<string> Names = new List<string>();
        public Box<int> IntBox = new Box<int>(1);
        public int[] Numbers = { 1, 2, 3 };
        public Point Origin;
    }

    // Every marshalled type, in and out (Phase 3 call matrix).
    public static class Calls
    {
        public static string StaticText = "static";
        public static int StaticNumber = 7;
        public static Point StaticPoint = new Point(1, 2);
        public const string ConstText = "const";

        public static bool Not(bool b) { return !b; }
        public static char NextChar(char c) { return (char)(c + 1); }
        public static sbyte NegI1(sbyte x) { return (sbyte)-x; }
        public static byte IncU1(byte x) { return (byte)(x + 1); }
        public static short NegI2(short x) { return (short)-x; }
        public static ushort IncU2(ushort x) { return (ushort)(x + 1); }
        public static int NegI4(int x) { return -x; }
        public static uint IncU4(uint x) { return x + 1; }
        public static long NegI8(long x) { return -x; }
        public static ulong IncU8(ulong x) { return x + 1; }
        public static float HalfR4(float x) { return x / 2; }
        public static double HalfR8(double x) { return x / 2; }
        public static IntPtr AddPtr(IntPtr p, int n) { return new IntPtr(p.ToInt64() + n); }
        public static long MaxLong() { return long.MaxValue; }
        public static ulong MaxULong() { return ulong.MaxValue; }

        public static string Concat(string a, string b) { return a + b; }
        public static string Echo(string s) { return s; }
        public static int Length(string s) { return s == null ? -1 : s.Length; }

        public static Color NextColor(Color c) { return c + 1; }
        public static Access Combine(Access a, Access b) { return a | b; }

        public static Point AddPoints(Point a, Point b) { return new Point(a.X + b.X, a.Y + b.Y); }
        public static Point MakePoint(int x, int y) { return new Point(x, y); }

        public static int SumArray(int[] xs) { int sum = 0; foreach (int x in xs) sum += x; return sum; }
        public static string[] Split(string s) { return s.Split(','); }
        public static int[] Range(int n) { int[] r = new int[n]; for (int i = 0; i < n; i++) r[i] = i; return r; }
        public static Point[] Points() { return new Point[] { new Point(1, 2), new Point(3, 4) }; }

        public static object Identity(object o) { return o; }
        public static string TypeName(Type t) { return t.FullName; }
        public static string TypeOf(object o) { return o == null ? "null" : o.GetType().FullName; }

        public static Animal MakeAnimal(string name) { return new Dog(name); }
        public static string Describe(Animal a) { return a.Name + " says " + a.Speak(); }
        public static int ListCount(List<string> list) { return list.Count; }

        public static void Throw(string message) { throw new InvalidOperationException(message); }
        public static int Divide(int a, int b) { return a / b; }

        public static int? NullableField;
        public static int? MaybeDouble(int? x) { return x.HasValue ? x * 2 : null; }
        public static bool HasValue(Point? p) { return p.HasValue; }

        public static void Fill(out int number, out string text, out Point point)
        {
            number = 42;
            text = "filled";
            point = new Point(5, 6);
        }

        public static void Twice(ref int number, ref string text)
        {
            number *= 2;
            text = text + text;
        }
    }

    public struct Vec3
    {
        public float X;
        public float Y;
        public float Z;

        public Vec3(float x, float y, float z)
        {
            X = x;
            Y = y;
            Z = z;
        }
    }

    public struct Big
    {
        public long A;
        public long B;
        public long C;
    }

    // Hook targets. NoInlining keeps the JIT from inlining them into the callers below.
    public class HookTargets
    {
        public int Value = 10;

        [MethodImpl(MethodImplOptions.NoInlining)]
        public virtual int Add(int x) { return Value + x; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Twice(int x) { return x * 2; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static string Greet(string name) { return "Hello " + name; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static double Scale(double value, float factor) { return value * factor; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static long Next(long x) { return x + 1; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static bool IsPositive(int x) { return x > 0; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Point Move(Point p, int dx) { return new Point(p.X + dx, p.Y); }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Vec3 Scale3(Vec3 v, float f) { return new Vec3(v.X * f, v.Y * f, v.Z * f); }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static Big Shift(Big b, long d) { Big r; r.A = b.A + d; r.B = b.B + d; r.C = b.C + d; return r; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static void Fill(int seed, out int result) { result = seed * 3; }

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Check(int x)
        {
            if (x < 0) throw new ArgumentException("negative");
            return x;
        }

        // Managed callers, so hooks are hit from JIT code and not only from our own invoke.
        public static int CallTwice(int x) { return Twice(x); }
        public static string CallGreet(string name) { return Greet(name); }
        public static double CallScale(double v, float f) { return Scale(v, f); }
        public static long CallNext(long x) { return Next(x); }
        public static bool CallIsPositive(int x) { return IsPositive(x); }
        public static int CallAdd(HookTargets t, int x) { return t.Add(x); }
        public static string CallMove(int x) { Point p = Move(new Point(x, 7), 1); return p.X + "," + p.Y; }
        public static string CallScale3(float x) { Vec3 v = Scale3(new Vec3(x, x + 1, x + 2), 2); return v.X + "," + v.Y + "," + v.Z; }
        public static string CallShift(long x) { Big b; b.A = x; b.B = x * 10; b.C = x * 100; Big r = Shift(b, 1); return r.A + "," + r.B + "," + r.C; }
        public static int CallFill(int seed) { int r; Fill(seed, out r); return r; }
        public static string CallCheck(int x) { try { return Check(x).ToString(); } catch (ArgumentException e) { return "caught " + e.Message; } }
    }

    // Calls a hook target from its own thread, to test hooks on threads Frida didn't attach.
    public static class Ticker
    {
        public static int Last = -1;
        static Thread thread;

        [MethodImpl(MethodImplOptions.NoInlining)]
        public static int Step(int i) { return i; }

        public static void Start()
        {
            if (thread != null) return;
            thread = new Thread(() => { for (int i = 0; ; i++) { Last = Step(i); Thread.Sleep(5); } });
            thread.IsBackground = true;
            thread.Start();
        }
    }

    public delegate double Combine(double x, Animal a);

    // Delegates created from JS functions (Phase 6).
    public static class Delegates
    {
        public static int Apply(Func<int, int> f, int x) { return f(x); }
        public static string Join(Func<string, string, string> f) { return f("a", "b"); }
        public static void Run(Action a) { a(); }
        public static Point MapPoint(Func<Point, Point> f) { return f(new Point(1, 2)); }
        public static double UseCombine(Combine c) { return c(1.5, new Dog("d")); }
        public static void Raise(Animal a) { a.OnRenamed(); }
    }
}
