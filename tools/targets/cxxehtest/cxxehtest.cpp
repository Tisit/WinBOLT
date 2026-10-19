// WinBolt runtime C++ EH test (DesignDoc Stage 6, "C++ EH functions").
//
// Functions with __CxxFrameHandler4 tables are moved as byte copies that share the original
// tables. This target throws C++ exceptions through such functions in every way the tables
// describe, so a wrong IP-to-state lookup, a wrong catch continuation or a missed destructor
// changes the output:
//   - destructors of locals run while an exception unwinds through a frame (unwind map);
//   - try/catch in a function that also holds objects (try block map, IP-to-state map);
//   - the catch continuation: code after the catch runs, with the frame's locals intact;
//   - rethrow from a catch, a new exception thrown from inside a catch, catch by base class;
//   - a function that catches, then continues and throws again from a later state.
// The output depends only on the program's logic.
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

static int alive = 0;
static int destroyed = 0;
static volatile int sink = 0;

struct Tracker
{
    int id;
    explicit Tracker(int i) : id(i) { alive++; }
    ~Tracker() { alive--; destroyed += id; }
};

struct AppError : std::runtime_error
{
    int code;
    AppError(const char *what, int c) : std::runtime_error(what), code(c) {}
};

__declspec(noinline) static void Thrower(int depth, int kind)
{
    Tracker t(depth);
    if (depth > 0)
    {
        Thrower(depth - 1, kind);
        sink += t.id;
        return;
    }

    switch (kind)
    {
    case 0:
        throw 42;
    case 1:
        throw AppError("app", 7);
    default:
        throw std::string("text");
    }
}

// Objects on both sides of a try: the IP-to-state map decides which destructors run.
__declspec(noinline) static int CatchAndContinue(int kind)
{
    Tracker before(100);
    std::vector<int> values{1, 2, 3};
    int result = 0;
    try
    {
        Tracker inside(1000);
        Thrower(3, kind);
        result = -1;
    }
    catch (int value)
    {
        result = value;
    }
    catch (const std::exception &e)
    {
        result = static_cast<int>(std::string(e.what()).size()) * 10;
    }
    catch (...)
    {
        result = 3;
    }

    // Continuation: the frame's locals must be intact.
    Tracker after(10000);
    for (int v : values)
    {
        result += v;
    }

    return result + before.id + after.id;
}

__declspec(noinline) static int Rethrow(int kind)
{
    Tracker t(5);
    try
    {
        Thrower(2, kind);
    }
    catch (...)
    {
        sink++;
        throw;
    }

    return 0;
}

__declspec(noinline) static int ThrowFromCatch()
{
    Tracker t(6);
    try
    {
        Thrower(1, 0);
    }
    catch (int value)
    {
        throw AppError("from catch", value + 1);
    }

    return 0;
}

// Catches, continues, then throws again from a later state of the same frame.
__declspec(noinline) static int TwoStates(int n)
{
    Tracker first(20);
    int total = 0;
    try
    {
        Thrower(n, 0);
    }
    catch (int value)
    {
        total += value;
    }

    Tracker second(30);
    std::string label = "state " + std::to_string(total);
    if (n > 1)
    {
        throw AppError(label.c_str(), total);
    }

    return total + static_cast<int>(label.size());
}

__declspec(noinline) static int Outer(int round)
{
    Tracker t(round);
    int score = 0;
    score += CatchAndContinue(round % 3);
    try
    {
        score += Rethrow(round % 3);
    }
    catch (int value)
    {
        score += value * 2;
    }
    catch (const AppError &e)
    {
        score += e.code * 3;
    }
    catch (const std::string &s)
    {
        score += static_cast<int>(s.size()) * 4;
    }

    try
    {
        score += ThrowFromCatch();
    }
    catch (const std::runtime_error &e)
    {
        score += static_cast<const AppError &>(e).code * 5;
    }

    try
    {
        score += TwoStates(round % 3);
    }
    catch (const AppError &e)
    {
        score += e.code * 7 + static_cast<int>(std::string(e.what()).size());
    }

    return score;
}

int main()
{
    long long total = 0;
    for (int round = 0; round < 30; round++)
    {
        int score = Outer(round);
        total += score;
        if (round < 6)
        {
            std::printf("round %d: score %d, alive %d, destroyed %d\n", round, score, alive, destroyed);
        }
    }

    std::printf("total %lld, alive %d, destroyed %d, sink %d\n", total, alive, destroyed, sink);
    return alive == 0 ? 0 : 1;
}
