using System;
using System.Data.SqlClient;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.Data.SqlClient;

namespace FunctionAppSmartRead
{
    public class Function1
    {
        private readonly ILogger<Function1> _logger;
        private readonly string _connectionString;

        public Function1(ILogger<Function1> logger)
        {
            _logger = logger;
            // Se obtiene la cadena de conexión de la variable de entorno "conexionSQL"
            _connectionString = Environment.GetEnvironmentVariable("conexionSQL")
                ?? throw new InvalidOperationException("La variable de entorno 'conexionSQL' no está configurada.");
        }

        [Function("Function1")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("Función ejecutada.");

            // Se obtienen los parámetros de consulta: username y password.
            string username = req.Query["username"];
            string password = req.Query["password"];

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return new BadRequestObjectResult("Debe proporcionar 'username' y 'password'.");
            }

            int userCount = 0;
            try
            {
                using (SqlConnection conn = new SqlConnection(_connectionString))
                {
                    await conn.OpenAsync();

                    // Escapar el nombre de la tabla usando corchetes.
                    string query = "SELECT COUNT(1) FROM [User] WHERE Username = @username AND password = @password";
                    using (SqlCommand cmd = new SqlCommand(query, conn))
                    {
                        cmd.Parameters.AddWithValue("@username", username);
                        cmd.Parameters.AddWithValue("@password", password);

                        object result = await cmd.ExecuteScalarAsync();
                        userCount = (result != null ? Convert.ToInt32(result) : 0);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error al consultar la base de datos: {ex.Message}");
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }

            if (userCount > 0)
            {
                return new OkObjectResult("Autenticación exitosa.");
            }
            else
            {
                return new UnauthorizedResult();
            }
        }
    }
}
