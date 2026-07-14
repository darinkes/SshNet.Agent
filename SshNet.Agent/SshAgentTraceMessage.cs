using System.Collections;
using System.Collections.Generic;

namespace SshNet.Agent
{
    /// <summary>
    /// One raw agent protocol message as structured log state: text sinks
    /// render the default summary line, structured sinks and custom loggers
    /// get <see cref="Direction"/> and the raw <see cref="Data"/> and choose
    /// their own representation.
    /// </summary>
    public readonly struct SshAgentTraceMessage : IReadOnlyList<KeyValuePair<string, object?>>
    {
        /// <summary>Whether the message went to or came from the agent.</summary>
        public SshAgentTraceDirection Direction { get; }

        /// <summary>The complete framed message, including the uint32 length prefix.</summary>
        public byte[] Data { get; }

        /// <summary>Captures one traced message.</summary>
        public SshAgentTraceMessage(SshAgentTraceDirection direction, byte[] data)
        {
            Direction = direction;
            Data = data;
        }

        /// <summary>The number of structured logging properties.</summary>
        public int Count => 4;

        /// <summary>The structured logging properties by index.</summary>
        public KeyValuePair<string, object?> this[int index] => index switch
        {
            0 => new KeyValuePair<string, object?>("Direction", Direction),
            1 => new KeyValuePair<string, object?>("DataLength", Data.Length),
            2 => new KeyValuePair<string, object?>("Data", Data),
            _ => new KeyValuePair<string, object?>("{OriginalFormat}", "{Direction} agent message, {DataLength} bytes"),
        };

        /// <summary>Enumerates the structured logging properties.</summary>
        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator()
        {
            for (var index = 0; index < Count; index++)
                yield return this[index];
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
