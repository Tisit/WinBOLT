using Iced.Intel;

namespace WinBolt.Core.Ir;

/// <summary>
/// Flat, append-only storage for decoded instructions (§5.3). A 100 MB image can hold on
/// the order of 10^7-10^8 instructions; one managed object each would put analysis into
/// GC-bound territory. <see cref="BasicBlock"/> stores an index range into this store
/// rather than a list of objects, and iced's <see cref="Instruction"/> value type is used
/// directly as the storage element.
/// </summary>
public sealed class InstructionStore
{
    private Instruction[] _items = new Instruction[64];
    private int _count;

    public int Count => _count;

    /// <summary>Appends an instruction and returns its index.</summary>
    public int Add(in Instruction instruction)
    {
        if (_count == _items.Length)
        {
            Array.Resize(ref _items, _items.Length * 2);
        }

        _items[_count] = instruction;
        return _count++;
    }

    public ref readonly Instruction this[int id]
    {
        get
        {
            if ((uint)id >= (uint)_count)
            {
                throw new ArgumentOutOfRangeException(nameof(id));
            }

            return ref _items[id];
        }
    }

    /// <summary>Returns the instructions for a contiguous ID range, e.g. one basic block.</summary>
    public ReadOnlySpan<Instruction> Slice(int start, int count) => _items.AsSpan(start, count);
}
