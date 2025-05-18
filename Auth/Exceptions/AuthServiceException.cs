namespace Lensisku.Auth.Exceptions
{
    public class AuthServiceException : System.Exception
    {
        public AuthServiceException(string message)
            : base(message) { }

        public AuthServiceException(string message, System.Exception innerException)
            : base(message, innerException) { }
    }
}