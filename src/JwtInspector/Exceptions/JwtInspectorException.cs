// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
namespace JwtInspector.Core.Exceptions
{
    /// <summary>
    /// Custom exception for errors in the JwtInspector library.
    /// </summary>
    public class JwtInspectorException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the JwtInspectorException class with a specified error message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        public JwtInspectorException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the JwtInspectorException class with a specified error message and a reference to the inner exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public JwtInspectorException(string message, Exception innerException) : base(message, innerException) { }
    }
}
