using System;
using System.Data.SqlClient;
using System.IO;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Data.SqlClient;  // Ojo: Microsoft.Data.SqlClient y System.Data.SqlClient

namespace FunctionAppSmartRead
{
    public class Function
    {
        private readonly ILogger<Function> _logger;
        private readonly string _connectionString;

        // Clave secreta para firmar el JWT (NO usar as� en producci�n).
        private const string SecretKey = "MiLlaveSecretaDeEjemplo1234567890AB";

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

            // Se obtiene el par�metro 'action' para determinar la operaci�n.
            string action = req.Query["action"];

            if (string.IsNullOrWhiteSpace(action))
            {
                return new BadRequestObjectResult("Debe proporcionar el par�metro 'action' (por ejemplo, 'login', 'register', 'sendcode', 'validate' o 'refreshtoken').");
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

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // Verificar si existe el usuario con esas credenciales.
                                string query = "SELECT COUNT(1) FROM [User] WHERE Username = @username AND Password = @password";
                                int userCount = 0;
                                using (SqlCommand cmd = new SqlCommand(query, conn))
                                {
                                    cmd.Parameters.AddWithValue("@username", username);
                                    cmd.Parameters.AddWithValue("@password", password);

                                    object result = await cmd.ExecuteScalarAsync();
                                    userCount = (result != null ? Convert.ToInt32(result) : 0);
                                }

                                if (userCount > 0)
                                {
                                    // Generar Access Token (JWT) y Refresh Token (JWT) con expiraci�n extendida.
                                    string accessToken = GenerateJwtToken(username);
                                    string refreshToken = GenerateRefreshJwtToken(username);

                                    // Retornar los tokens al cliente para que se guarden en la app.
                                    return new OkObjectResult(new
                                    {
                                        AccessToken = accessToken,
                                        RefreshToken = refreshToken
                                    });
                                }
                                else
                                {
                                    // Usuario o contrase�a inv�lidos.
                                    return new UnauthorizedResult();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al consultar la base de datos: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
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

                                // Verificar si el usuario o el correo ya existen.
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

                                // Insertar nuevo usuario.
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

                case "sendcode":
                    {
                        // Genera un n�mero aleatorio de 4 d�gitos (entre 1000 y 9999).
                        Random random = new Random();
                        int randomCode = random.Next(1000, 10000);
                        return new OkObjectResult(randomCode);
                    }

              

                default:
                    return new BadRequestObjectResult("La acci�n especificada no es v�lida. Use 'login', 'register', 'sendcode', 'validate' o 'refreshtoken'.");
            }
        }

        /// <summary>
        /// Genera un Access Token (JWT) con una expiraci�n de 60 minutos.
        /// </summary>
        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: "tu-issuer",       
                audience: "tu-audience",  
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Genera un Refresh Token (JWT) con una expiraci�n de 7 d�as.
        /// </summary>
        private string GenerateRefreshJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: "tu-issuer",       
                audience: "tu-audience",   
                claims: claims,
                expires: DateTime.UtcNow.AddDays(7),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}
