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
    public class Function
    {
        private readonly ILogger<Function> _logger;
        private readonly string _connectionString;

        public Function(ILogger<Function> logger)
        {
            _logger = logger;
            _connectionString = Environment.GetEnvironmentVariable("conexionSQL")
                ?? throw new InvalidOperationException("La variable de entorno 'conexionSQL' no est� configurada.");
        }

        [Function("Function")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("Funci�n combinada ejecutada.");

            // Se obtiene el par�metro 'action' para determinar la operaci�n
            string action = req.Query["action"];

            if (string.IsNullOrWhiteSpace(action))
            {
                return new BadRequestObjectResult("Debe proporcionar el par�metro 'action' (por ejemplo, 'login' o 'register').");
            }

            switch (action.ToLower())
            {
                case "login":
                case "auth":
                    {
                        // L�gica de autenticaci�n
                        string username = req.Query["username"];
                        string password = req.Query["password"];

                        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                        {
                            return new BadRequestObjectResult("Para autenticaci�n, debe proporcionar 'username' y 'password'.");
                        }

                        int userCount = 0;
                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                string query = "SELECT COUNT(1) FROM [User] WHERE Username = @username AND Password = @password";
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

                        return userCount > 0
                            ? new OkObjectResult("Autenticaci�n exitosa.")
                            : new UnauthorizedResult();
                    }

                case "register":
                    {
                        // L�gica de registro
                        string username = req.Query["username"];
                        string password = req.Query["password"];
                        string email = req.Query["email"];

                        if (string.IsNullOrWhiteSpace(username) ||
                            string.IsNullOrWhiteSpace(password) ||
                            string.IsNullOrWhiteSpace(email))
                        {
                            return new BadRequestObjectResult("Para registro, debe proporcionar 'username', 'password' y 'email'.");
                        }

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // Verificar si el usuario o el correo ya existen
                                string checkQuery = "SELECT COUNT(1) FROM [User] WHERE Username = @username OR Email = @email";
                                using (SqlCommand checkCmd = new SqlCommand(checkQuery, conn))
                                {
                                    checkCmd.Parameters.AddWithValue("@username", username);
                                    checkCmd.Parameters.AddWithValue("@email", email);
                                    object checkResult = await checkCmd.ExecuteScalarAsync();
                                    int existingUserCount = (checkResult != null ? Convert.ToInt32(checkResult) : 0);

                                    if (existingUserCount > 0)
                                    {
                                        return new ConflictObjectResult("El usuario o el correo ya existen.");
                                    }
                                }

                                // Insertar nuevo usuario
                                string insertQuery = "INSERT INTO [User] (Username, Password, Email) VALUES (@username, @password, @email)";
                                using (SqlCommand insertCmd = new SqlCommand(insertQuery, conn))
                                {
                                    insertCmd.Parameters.AddWithValue("@username", username);
                                    insertCmd.Parameters.AddWithValue("@password", password);
                                    insertCmd.Parameters.AddWithValue("@email", email);

                                    int rowsAffected = await insertCmd.ExecuteNonQueryAsync();
                                    return rowsAffected > 0
                                        ? new OkObjectResult("Usuario registrado exitosamente.")
                                        : new StatusCodeResult(StatusCodes.Status500InternalServerError);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al registrar usuario: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                default:
                    return new BadRequestObjectResult("La acci�n especificada no es v�lida. Use 'login' o 'register'.");
            }
        }
    }
}