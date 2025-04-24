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
using Microsoft.Data.SqlClient;
using System.Collections.Generic;

namespace FunctionAppSmartRead
{
    public class Function
    {
        private readonly ILogger<Function> _logger;
        private readonly string _connectionString;
        private readonly string SecretKey;

        public Function(ILogger<Function> logger)
        {
            _logger = logger;

            _connectionString = Environment.GetEnvironmentVariable("conexionSQL")
                ?? throw new InvalidOperationException("La variable de entorno 'conexionSQL' no est� configurada.");

            SecretKey = Environment.GetEnvironmentVariable("SecretKey")
                ?? throw new InvalidOperationException("La variable de entorno 'SecretKey' no est� configurada.");
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
                return new BadRequestObjectResult("Debe proporcionar el par�metro 'action' (por ejemplo, 'login', 'register', 'sendcode', 'validatecode', 'validate', 'refreshtoken', 'getcategories' o 'getmorebooks').");
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
                        // Se obtiene el par�metro 'email'
                        string email = req.Query["email"];
                        if (string.IsNullOrWhiteSpace(email))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el par�metro 'email'.");
                        }

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // 1. Verificar que exista un usuario con ese email y obtener su id_user
                                string getUserQuery = "SELECT id_user FROM [User] WHERE Email = @Email";
                                object userIdObj;
                                using (SqlCommand getUserCmd = new SqlCommand(getUserQuery, conn))
                                {
                                    getUserCmd.Parameters.AddWithValue("@Email", email);
                                    userIdObj = await getUserCmd.ExecuteScalarAsync();
                                }

                                if (userIdObj == null)
                                {
                                    // No se encontr� un usuario con el email proporcionado
                                    return new BadRequestObjectResult("No se encontr� un usuario con ese correo electr�nico.");
                                }

                                int userId = Convert.ToInt32(userIdObj);

                                // 2. Generar un n�mero aleatorio de 4 d�gitos (entre 1000 y 9999)
                                Random random = new Random();
                                int randomCode = random.Next(1000, 10000);

                                // 3. Insertar el token en la tabla 'password_reset_token'
                                string insertQuery = @"
                                    INSERT INTO password_reset_token (id_user, token, created_at, expires_at)
                                    VALUES (@id_user, @token, @created_at, @expires_at)";

                                using (SqlCommand insertCmd = new SqlCommand(insertQuery, conn))
                                {
                                    insertCmd.Parameters.AddWithValue("@id_user", userId);
                                    insertCmd.Parameters.AddWithValue("@token", randomCode.ToString());
                                    insertCmd.Parameters.AddWithValue("@created_at", DateTime.UtcNow);
                                    insertCmd.Parameters.AddWithValue("@expires_at", DateTime.UtcNow.AddMinutes(15));
                                    await insertCmd.ExecuteNonQueryAsync();
                                }

                                // 4. Enviar el correo electr�nico con el c�digo
                                string smtpHost = Environment.GetEnvironmentVariable("SMTP_HOST") ?? "smtp.gmail.com";
                                string smtpUser = Environment.GetEnvironmentVariable("SMTP_USER") ?? "smartreadteam@gmail.com";
                                string smtpPass = Environment.GetEnvironmentVariable("SMTP_PASS");
                                int smtpPort = Convert.ToInt32(Environment.GetEnvironmentVariable("SMTP_PORT") ?? "587");

                                using (var client = new System.Net.Mail.SmtpClient(smtpHost, smtpPort))
                                {
                                    client.Credentials = new System.Net.NetworkCredential(smtpUser, smtpPass);
                                    client.EnableSsl = true;

                                    using (var mailMessage = new System.Net.Mail.MailMessage())
                                    {
                                        mailMessage.From = new System.Net.Mail.MailAddress(smtpUser);
                                        mailMessage.To.Add(email);
                                        mailMessage.Subject = "C�digo de recuperaci�n de contrase�a";
                                        mailMessage.Body = $"Tu c�digo de recuperaci�n es: {randomCode}";

                                        await client.SendMailAsync(mailMessage);
                                    }
                                }

                                // 5. Retornar mensaje de �xito sin retornar el c�digo generado
                                return new OkObjectResult("El c�digo se ha enviado correctamente al correo.");
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al procesar la solicitud: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                case "validatecode":
                    {
                        // Se reciben los par�metros 'email' y 'resetcode'
                        string email = req.Query["email"];
                        string resetCode = req.Query["resetcode"];
                        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(resetCode))
                        {
                            return new BadRequestObjectResult("Debe proporcionar los par�metros 'email' y 'resetcode'.");
                        }

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // 1. Obtener el id_user asociado al email
                                string getUserQuery = "SELECT id_user FROM [User] WHERE Email = @Email";
                                object userIdObj;
                                using (SqlCommand getUserCmd = new SqlCommand(getUserQuery, conn))
                                {
                                    getUserCmd.Parameters.AddWithValue("@Email", email);
                                    userIdObj = await getUserCmd.ExecuteScalarAsync();
                                }

                                if (userIdObj == null)
                                {
                                    return new OkObjectResult(new { IsValid = false });
                                }

                                int userId = Convert.ToInt32(userIdObj);
                                DateTime currentTime = DateTime.UtcNow;

                                // 2. Verificar que exista un token v�lido para ese usuario y c�digo          
                                string tokenQuery = @"
                                    SELECT COUNT(1) 
                                    FROM password_reset_token
                                    WHERE id_user = @id_user 
                                    AND token = @resetCode 
                                    AND expires_at > @currentTime";
                                int count = 0;
                                using (SqlCommand tokenCmd = new SqlCommand(tokenQuery, conn))
                                {
                                    tokenCmd.Parameters.AddWithValue("@id_user", userId);
                                    tokenCmd.Parameters.AddWithValue("@resetCode", resetCode);
                                    tokenCmd.Parameters.AddWithValue("@currentTime", currentTime);
                                    object result = await tokenCmd.ExecuteScalarAsync();
                                    count = (result != null ? Convert.ToInt32(result) : 0);
                                }

                                _logger.LogInformation($"Verificando token para userId {userId}: resetCode = {resetCode}, currentTime = {currentTime}, count = {count}");

                                bool isValid = count > 0;
                                return new OkObjectResult(new { IsValid = isValid });
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al validar el c�digo: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                case "validate":
                    {
                        // Recibe el par�metro 'accesstoken' para validarlo.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el par�metro 'accesstoken'.");
                        }

                        bool isValid = IsTokenValid(accessToken);
                        return new OkObjectResult(isValid);
                    }

                case "refreshtoken":
                    {
                        // Se espera que el cliente env�e el par�metro 'refreshToken' y 'username'.
                        string refreshToken = req.Query["refreshToken"];
                        string username = req.Query["username"];
                        if (string.IsNullOrWhiteSpace(refreshToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el par�metro 'refreshToken'.");
                        }
                        if (string.IsNullOrWhiteSpace(username))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el par�metro 'username'.");
                        }

                        // Validar el refresh token.
                        if (!IsTokenValid(refreshToken))
                        {
                            return new UnauthorizedResult();
                        }

                        // Extraer el usuario del refresh token para verificar que coincida con el par�metro 'username'.
                        var tokenHandler = new JwtSecurityTokenHandler();
                        SecurityToken validatedToken;
                        var principal = tokenHandler.ValidateToken(refreshToken, new TokenValidationParameters
                        {
                            ValidateIssuerSigningKey = true,
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey)),
                            ValidateIssuer = true,
                            ValidIssuer = "tu-issuer",
                            ValidateAudience = true,
                            ValidAudience = "tu-audience",
                            ClockSkew = TimeSpan.Zero
                        }, out validatedToken);

                        var tokenUsername = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
                        if (tokenUsername != username)
                        {
                            return new UnauthorizedResult();
                        }

                        // Generar nuevos tokens
                        string newAccessToken = GenerateJwtToken(username);
                        string newRefreshToken = GenerateRefreshJwtToken(username);
                        return new OkObjectResult(new
                        {
                            AccessToken = newAccessToken,
                            RefreshToken = newRefreshToken
                        });
                    }

                case "getcategories":
                    {
                        // Se valida que se env�e el access token
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el par�metro 'accesstoken'.");
                        }

                        // Se valida que el token sea correcto y no haya expirado
                        if (!IsTokenValid(accessToken))
                        {
                            return new UnauthorizedResult();
                        }

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // Consulta para obtener la lista de categor�as
                                string query = "SELECT id_category, name FROM category";
                                var categories = new List<object>();

                                using (SqlCommand cmd = new SqlCommand(query, conn))
                                using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                                {
                                    while (await reader.ReadAsync())
                                    {
                                        categories.Add(new
                                        {
                                            IdCategory = reader.GetInt32(0),
                                            Name = reader.GetString(1)
                                        });
                                    }
                                }

                                // Retornar la lista de categor�as en formato JSON
                                return new OkObjectResult(categories);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener la lista de categor�as: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                // Nueva acci�n: Obtener m�s libros por categor�a (getmorebooks)
                case "getbooksbycategory":
                    {
                        // Validar que se reciba el par�metro 'accesstoken'.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el par�metro 'accesstoken'.");
                        }

                        // Validar que el token sea correcto.
                        if (!IsTokenValid(accessToken))
                        {
                            return new UnauthorizedResult();
                        }

                        // Validar que se reciba el 'categoryId' y que �ste sea un n�mero entero v�lido.
                        string categoryIdStr = req.Query["categoryId"];
                        if (string.IsNullOrWhiteSpace(categoryIdStr) || !int.TryParse(categoryIdStr, out int categoryId))
                        {
                            return new BadRequestObjectResult("Debe proporcionar un 'categoryId' v�lido.");
                        }

                        // Obtener par�metros de paginaci�n: offset y limit.
                        int offset = 0;
                        int limit = 10; // Valor por defecto
                        string offsetStr = req.Query["offset"];
                        string limitStr = req.Query["limit"];

                        if (!string.IsNullOrWhiteSpace(offsetStr) && !int.TryParse(offsetStr, out offset))
                        {
                            return new BadRequestObjectResult("El par�metro 'offset' debe ser un n�mero entero v�lido.");
                        }
                        if (!string.IsNullOrWhiteSpace(limitStr) && !int.TryParse(limitStr, out limit))
                        {
                            return new BadRequestObjectResult("El par�metro 'limit' debe ser un n�mero entero v�lido.");
                        }

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // Consulta para obtener los libros asociados a la categor�a con paginaci�n.
                                // Se utilizan OFFSET y FETCH NEXT para limitar los resultados.
                                string query = @"
                SELECT b.id_book, b.title, b.published_date, b.author, b.file_path, b.description
                FROM book b
                INNER JOIN book_category bc ON b.id_book = bc.id_book
                WHERE bc.id_category = @categoryId
                ORDER BY b.id_book
                OFFSET @offset ROWS FETCH NEXT @limit ROWS ONLY";

                                var books = new List<object>();
                                using (SqlCommand cmd = new SqlCommand(query, conn))
                                {
                                    cmd.Parameters.AddWithValue("@categoryId", categoryId);
                                    cmd.Parameters.AddWithValue("@offset", offset);
                                    cmd.Parameters.AddWithValue("@limit", limit);

                                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                                    {
                                        while (await reader.ReadAsync())
                                        {
                                            int idBook = reader.GetInt32(0);
                                            string title = reader.GetString(1);
                                            DateTime? publishedDate = reader.IsDBNull(2) ? (DateTime?)null : reader.GetDateTime(2);
                                            string author = reader.GetString(3);
                                            string filePath = reader.GetString(4);
                                            // Aqu� se maneja el caso en que la descripci�n es nula.
                                            string description = reader.IsDBNull(5) ? "" : reader.GetString(5);

                                            books.Add(new
                                            {
                                                IdBook = idBook,
                                                Title = title,
                                                PublishedDate = publishedDate,
                                                Author = author,
                                                FilePath = filePath,
                                                Description = description
                                            });
                                        }
                                    }
                                }
                                // Retorna la lista de libros en formato JSON.
                                return new OkObjectResult(books);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener libros para la categor�a {categoryId}: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                case "getrecentbooks":
                    {
                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // Trae los 10 libros con fecha de publicaci�n m�s reciente
                                string query = @"
                                    SELECT TOP 10 
                                        b.id_book, 
                                        b.title, 
                                        b.published_date, 
                                        b.author, 
                                        b.file_path, 
                                        b.description
                                    FROM dbo.book b
                                    ORDER BY b.published_date DESC";

                                var books = new List<object>();
                                using (SqlCommand cmd = new SqlCommand(query, conn))
                                using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                                {
                                    while (await reader.ReadAsync())
                                    {
                                        int idBook = reader.GetInt32(0);
                                        string title = reader.GetString(1);
                                        DateTime? publishedDate = reader.IsDBNull(2)
                                            ? (DateTime?)null
                                            : reader.GetDateTime(2);
                                        string author = reader.GetString(3);
                                        string filePath = reader.GetString(4);
                                        string description = reader.IsDBNull(5)
                                            ? ""
                                            : reader.GetString(5);

                                        books.Add(new
                                        {
                                            IdBook = idBook,
                                            Title = title,
                                            PublishedDate = publishedDate,
                                            Author = author,
                                            FilePath = filePath,
                                            Description = description
                                        });
                                    }
                                }

                                return new OkObjectResult(books);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener libros recientes: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }



                default:
                    return new BadRequestObjectResult("La acci�n especificada no es v�lida. Use 'login', 'register', 'sendcode', 'validatecode', 'validate', 'refreshtoken', 'getcategories' o 'getmorebooks'.");
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

        /// <summary>
        /// Valida el token (JWT) usando la misma clave secreta y par�metros de validaci�n.
        /// Retorna true si el token es v�lido y no ha expirado; de lo contrario, false.
        /// </summary>
        private bool IsTokenValid(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(SecretKey);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = "tu-issuer",
                ValidateAudience = true,
                ValidAudience = "tu-audience",
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
