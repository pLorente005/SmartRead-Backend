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
using System.Text.Json;
using static System.Runtime.InteropServices.JavaScript.JSType;
using Stripe;

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
                ?? throw new InvalidOperationException("La variable de entorno 'conexionSQL' no está configurada.");

            SecretKey = Environment.GetEnvironmentVariable("SecretKey")
                ?? throw new InvalidOperationException("La variable de entorno 'SecretKey' no está configurada.");
        }

        [Function("Function")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post")] HttpRequest req)
        {
            _logger.LogInformation("Función combinada ejecutada.");

            // Se obtiene el parámetro 'action' para determinar la operación.
            string action = req.Query["action"];

            if (string.IsNullOrWhiteSpace(action))
            {
                return new BadRequestObjectResult("Debe proporcionar el parámetro 'action' (por ejemplo, 'login', 'register', 'sendcode', 'validatecode', 'validate', 'refreshtoken', 'getcategories' o 'getmorebooks').");
            }

            switch (action.ToLower())
            {
                case "login":
                case "auth":
                    {
                        // Lógica de autenticación
                        string username = req.Query["username"];
                        string password = req.Query["password"];

                        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                        {
                            return new BadRequestObjectResult("Para autenticación, debe proporcionar 'username' y 'password'.");
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
                                    // Generar Access Token (JWT) y Refresh Token (JWT) con expiración extendida.
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
                                    // Usuario o contraseña inválidos.
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
                        // 1) Leer parámetros
                        string username = req.Query["username"];
                        string password = req.Query["password"];
                        string email = req.Query["email"];
                        string sessionId = req.Query["sessionId"];

                        if (string.IsNullOrWhiteSpace(username) ||
                            string.IsNullOrWhiteSpace(password) ||
                            string.IsNullOrWhiteSpace(email) ||
                            string.IsNullOrWhiteSpace(sessionId))
                        {
                            return new BadRequestObjectResult(
                                "Para registro, debe proporcionar 'username', 'password', 'email' y 'sessionId'.");
                        }

                        try
                        {
                            // 2) Obtener sesión de Stripe y validar uso/pago
                            StripeConfiguration.ApiKey = Environment.GetEnvironmentVariable("STRIPE_SECRET_KEY");
                            var sessionService = new Stripe.Checkout.SessionService();
                            var stripeSession = await sessionService.GetAsync(sessionId);

                            // 2a) Verificar si ya se usó esta sesión
                            if (stripeSession.Metadata.TryGetValue("used", out var used) && used == "true")
                            {
                                return new BadRequestObjectResult("Esta sesión de pago ya ha sido utilizada.");
                            }

                            // 2b) Verificar que el pago se completó
                            if (stripeSession.PaymentStatus != "paid")
                            {
                                return new BadRequestObjectResult("El pago no se ha completado correctamente.");
                            }

                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // 3) Verificar si el usuario o el correo ya existen
                                const string checkUserSql = @"
                SELECT COUNT(1)
                FROM [User]
                WHERE Username = @username OR Email = @email";
                                using (var checkUserCmd = new SqlCommand(checkUserSql, conn))
                                {
                                    checkUserCmd.Parameters.AddWithValue("@username", username);
                                    checkUserCmd.Parameters.AddWithValue("@email", email);
                                    int existingUserCount = Convert.ToInt32(await checkUserCmd.ExecuteScalarAsync());
                                    if (existingUserCount > 0)
                                    {
                                        return new ConflictObjectResult("El usuario o el correo ya existen.");
                                    }
                                }

                                // 4) Insertar nuevo usuario
                                const string insertUserSql = @"
                INSERT INTO [User] (Username, Password, Email)
                VALUES (@username, @password, @email)";
                                using (var insertUserCmd = new SqlCommand(insertUserSql, conn))
                                {
                                    insertUserCmd.Parameters.AddWithValue("@username", username);
                                    insertUserCmd.Parameters.AddWithValue("@password", password);
                                    insertUserCmd.Parameters.AddWithValue("@email", email);

                                    int rowsAffected = await insertUserCmd.ExecuteNonQueryAsync();
                                    if (rowsAffected <= 0)
                                    {
                                        return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                                    }
                                }
                            }

                            // 5) Marcar sessionId como usado en metadata de Stripe tras registro exitoso
                            var updateOptions = new Stripe.Checkout.SessionUpdateOptions
                            {
                                Metadata = new Dictionary<string, string>
            {
                { "used", "true" }
            }
                            };
                            await sessionService.UpdateAsync(sessionId, updateOptions);

                            return new OkObjectResult("Usuario registrado exitosamente.");
                        }
                        catch (StripeException sx)
                        {
                            _logger.LogError($"Error al comprobar el pago en Stripe: {sx.Message}");
                            return new StatusCodeResult(StatusCodes.Status502BadGateway);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al registrar usuario: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                case "sendcode":
                    {
                        // Se obtiene el parámetro 'email'
                        string email = req.Query["email"];
                        if (string.IsNullOrWhiteSpace(email))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'email'.");
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
                                    // No se encontró un usuario con el email proporcionado
                                    return new BadRequestObjectResult("No se encontró un usuario con ese correo electrónico.");
                                }

                                int userId = Convert.ToInt32(userIdObj);

                                // 2. Generar un número aleatorio de 4 dígitos (entre 1000 y 9999)
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

                                // 4. Enviar el correo electrónico con el código
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
                                        mailMessage.Subject = "Código de recuperación de contraseña";
                                        mailMessage.Body = $"Tu código de recuperación es: {randomCode}";

                                        await client.SendMailAsync(mailMessage);
                                    }
                                }

                                // 5. Retornar mensaje de éxito sin retornar el código generado
                                return new OkObjectResult("El código se ha enviado correctamente al correo.");
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
                        // Se reciben los parámetros 'email' y 'resetcode'
                        string email = req.Query["email"];
                        string resetCode = req.Query["resetcode"];
                        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(resetCode))
                        {
                            return new BadRequestObjectResult("Debe proporcionar los parámetros 'email' y 'resetcode'.");
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

                                // 2. Verificar que exista un token válido para ese usuario y código          
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
                            _logger.LogError($"Error al validar el código: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                case "validate":
                    {
                        // Recibe el parámetro 'accesstoken' para validarlo.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        }

                        bool isValid = IsTokenValid(accessToken);
                        return new OkObjectResult(isValid);
                    }

                case "refreshtoken":
                    {
                        // Se espera que el cliente envíe el parámetro 'refreshToken' y 'username'.
                        string refreshToken = req.Query["refreshToken"];
                        string username = req.Query["username"];
                        if (string.IsNullOrWhiteSpace(refreshToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'refreshToken'.");
                        }
                        if (string.IsNullOrWhiteSpace(username))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'username'.");
                        }

                        // Validar el refresh token.
                        if (!IsTokenValid(refreshToken))
                        {
                            return new UnauthorizedResult();
                        }

                        // Extraer el usuario del refresh token para verificar que coincida con el parámetro 'username'.
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
                        // Se valida que se envíe el access token
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
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

                                // Consulta para obtener la lista de categorías
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

                                // Retornar la lista de categorías en formato JSON
                                return new OkObjectResult(categories);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener la lista de categorías: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                // Nueva acción: Obtener más libros por categoría (getmorebooks)
                case "getbooksbycategory":
                    {
                        // Validar que se reciba el parámetro 'accesstoken'.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        }

                        // Validar que el token sea correcto.
                        if (!IsTokenValid(accessToken))
                        {
                            return new UnauthorizedResult();
                        }

                        // Validar que se reciba el 'categoryId' y que éste sea un número entero válido.
                        string categoryIdStr = req.Query["categoryId"];
                        if (string.IsNullOrWhiteSpace(categoryIdStr) || !int.TryParse(categoryIdStr, out int categoryId))
                        {
                            return new BadRequestObjectResult("Debe proporcionar un 'categoryId' válido.");
                        }

                        // Obtener parámetros de paginación: offset y limit.
                        int offset = 0;
                        int limit = 10; // Valor por defecto
                        string offsetStr = req.Query["offset"];
                        string limitStr = req.Query["limit"];

                        if (!string.IsNullOrWhiteSpace(offsetStr) && !int.TryParse(offsetStr, out offset))
                        {
                            return new BadRequestObjectResult("El parámetro 'offset' debe ser un número entero válido.");
                        }
                        if (!string.IsNullOrWhiteSpace(limitStr) && !int.TryParse(limitStr, out limit))
                        {
                            return new BadRequestObjectResult("El parámetro 'limit' debe ser un número entero válido.");
                        }

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // Consulta para obtener los libros asociados a la categoría con paginación.
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
                                            // Aquí se maneja el caso en que la descripción es nula.
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
                            _logger.LogError($"Error al obtener libros para la categoría {categoryId}: {ex.Message}");
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

                                // Trae los 10 libros con fecha de publicación más reciente
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
                case "addreview":
                    {
                        // 1) Validar que se reciba el parámetro 'accesstoken'.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");

                        // 2) Validar que el token sea correcto.
                        if (!IsTokenValid(accessToken))
                            return new UnauthorizedResult();

                        // 3) Extraer el username desde el token
                        string username = GetUsernameFromToken(accessToken);
                        if (username == null)
                        {
                            _logger.LogWarning("Access token válido pero sin claim de usuario.");
                            return new UnauthorizedResult();
                        }
                        _logger.LogInformation($"Usuario extraído: {username}");

                        // 4) Leer y validar parámetros de la petición
                        if (!int.TryParse(req.Query["bookId"], out int bookId))
                            return new BadRequestObjectResult("Parámetro 'bookId' inválido o ausente.");
                        if (!int.TryParse(req.Query["rating"], out int rating) || rating < 1 || rating > 5)
                            return new BadRequestObjectResult("Parámetro 'rating' inválido. Debe ser un número entre 1 y 5.");
                        string comment = req.Query["comment"];

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // 5) Obtener id_user a partir del username
                                int userId;
                                using (var cmdUser = new SqlCommand(
                                    "SELECT id_user FROM [User] WHERE Username = @username", conn))
                                {
                                    cmdUser.Parameters.AddWithValue("@username", username);
                                    object res = await cmdUser.ExecuteScalarAsync();
                                    if (res == null)
                                        return new BadRequestObjectResult("Usuario no encontrado.");
                                    userId = Convert.ToInt32(res);
                                }

                                // 6) Comprobar si ya existe una review para este user+book
                                const string checkReviewSql = @"
                                    SELECT COUNT(1)
                                    FROM dbo.review
                                    WHERE id_user = @id_user
                                      AND id_book = @id_book";
                                int reviewCount;
                                using (var cmdCheckReview = new SqlCommand(checkReviewSql, conn))
                                {
                                    cmdCheckReview.Parameters.AddWithValue("@id_user", userId);
                                    cmdCheckReview.Parameters.AddWithValue("@id_book", bookId);
                                    reviewCount = Convert.ToInt32(await cmdCheckReview.ExecuteScalarAsync());
                                }

                                if (reviewCount > 0)
                                {
                                    // 7a) Si ya tenía review, la actualizamos
                                    const string updateReviewSql = @"
                                        UPDATE dbo.review
                                        SET rating = @rating,
                                            comment = @comment,
                                            review_date = SYSDATETIME()
                                        WHERE id_user = @id_user
                                          AND id_book = @id_book";
                                    using (var cmdUpdate = new SqlCommand(updateReviewSql, conn))
                                    {
                                        cmdUpdate.Parameters.AddWithValue("@id_user", userId);
                                        cmdUpdate.Parameters.AddWithValue("@id_book", bookId);
                                        cmdUpdate.Parameters.AddWithValue("@rating", rating);
                                        cmdUpdate.Parameters.AddWithValue("@comment", comment ?? string.Empty);
                                        await cmdUpdate.ExecuteNonQueryAsync();
                                    }
                                }
                                else
                                {
                                    // 7b) Si no existía, insertamos nueva review
                                    const string insertReviewSql = @"
                                        INSERT INTO dbo.review (
                                            id_user,
                                            id_book,
                                            rating,
                                            comment,
                                            review_date
                                        ) VALUES (
                                            @id_user,
                                            @id_book,
                                            @rating,
                                            @comment,
                                            SYSDATETIME()
                                        )";
                                    using (var cmdReview = new SqlCommand(insertReviewSql, conn))
                                    {
                                        cmdReview.Parameters.AddWithValue("@id_user", userId);
                                        cmdReview.Parameters.AddWithValue("@id_book", bookId);
                                        cmdReview.Parameters.AddWithValue("@rating", rating);
                                        cmdReview.Parameters.AddWithValue("@comment", comment ?? string.Empty);
                                        await cmdReview.ExecuteNonQueryAsync();
                                    }
                                }

                                // 8) Gestionar favorites según valoración
                                //    Umbral: rating >= 3 → favorito; rating < 3 → eliminar de favoritos.
                                if (rating >= 3)
                                {
                                    // Añadir a favorites si no existe
                                    const string checkFavSql = @"
                                        SELECT COUNT(1)
                                        FROM dbo.favorites
                                        WHERE id_user = @id_user
                                          AND id_book = @id_book";
                                    int favCount;
                                    using (var cmdCheckFav = new SqlCommand(checkFavSql, conn))
                                    {
                                        cmdCheckFav.Parameters.AddWithValue("@id_user", userId);
                                        cmdCheckFav.Parameters.AddWithValue("@id_book", bookId);
                                        favCount = Convert.ToInt32(await cmdCheckFav.ExecuteScalarAsync());
                                    }

                                    if (favCount == 0)
                                    {
                                        const string insertFavSql = @"
                                            INSERT INTO dbo.favorites (
                                                id_user,
                                                id_book,
                                                created_at
                                            ) VALUES (
                                                @id_user,
                                                @id_book,
                                                SYSDATETIME()
                                            )";
                                        using (var cmdFav = new SqlCommand(insertFavSql, conn))
                                        {
                                            cmdFav.Parameters.AddWithValue("@id_user", userId);
                                            cmdFav.Parameters.AddWithValue("@id_book", bookId);
                                            await cmdFav.ExecuteNonQueryAsync();
                                        }
                                    }
                                }
                                else
                                {
                                    // Quitar de favorites si existía
                                    const string deleteFavSql = @"
                                        DELETE FROM dbo.favorites
                                        WHERE id_user = @id_user
                                          AND id_book = @id_book";
                                    using (var cmdDelFav = new SqlCommand(deleteFavSql, conn))
                                    {
                                        cmdDelFav.Parameters.AddWithValue("@id_user", userId);
                                        cmdDelFav.Parameters.AddWithValue("@id_book", bookId);
                                        await cmdDelFav.ExecuteNonQueryAsync();
                                    }
                                }
                            }

                            return new OkObjectResult("Valoración procesada correctamente.");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al insertar/actualizar valoración o favoritos: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "getpopularbooks":
                    {
                        // Validar que se reciba el parámetro 'accesstoken'.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        }

                        // Validar que el token sea correcto.
                        if (!IsTokenValid(accessToken))
                        {
                            return new UnauthorizedResult();
                        }
                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();
                                string query = @"
                                    SELECT TOP 10 
                                        b.id_book, 
                                        b.title, 
                                        b.published_date, 
                                        b.author, 
                                        b.file_path, 
                                        b.description
                                    FROM dbo.book b
                                    LEFT JOIN dbo.review r ON b.id_book = r.id_book
                                    GROUP BY 
                                        b.id_book, b.title, b.published_date, b.author, b.file_path, b.description
                                    ORDER BY COUNT(r.id_review) DESC";

                                var books = new List<object>();
                                using (SqlCommand cmd = new SqlCommand(query, conn))
                                using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                                {
                                    while (await reader.ReadAsync())
                                    {
                                        int idBook = reader.GetInt32(0);
                                        string title = reader.GetString(1);
                                        DateTime? publishedDate = reader.IsDBNull(2) ? (DateTime?)null : reader.GetDateTime(2);
                                        string author = reader.GetString(3);
                                        string filePath = reader.GetString(4);
                                        string description = reader.IsDBNull(5) ? string.Empty : reader.GetString(5);

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
                            _logger.LogError($"Error al obtener libros populares: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "addtolist":
                    {
                        // Validar que se reciba el parámetro 'accesstoken'.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        }

                        // Validar que el token sea correcto.
                        if (!IsTokenValid(accessToken))
                        {
                            return new UnauthorizedResult();
                        }

                        // 2) Extraer usuario
                        string username = GetUsernameFromToken(accessToken);
                        if (username == null)
                            return new UnauthorizedResult();

                        // 3) Validar parámetro bookId
                        if (!int.TryParse(req.Query["bookId"], out int bookId))
                            return new BadRequestObjectResult("Parámetro 'bookId' inválido o ausente.");

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // 4) Obtener id_user
                                int userId;
                                using (var cmdUser = new SqlCommand(
                                    "SELECT id_user FROM [User] WHERE Username = @username", conn))
                                {
                                    cmdUser.Parameters.AddWithValue("@username", username);
                                    object res = await cmdUser.ExecuteScalarAsync();
                                    if (res == null)
                                        return new BadRequestObjectResult("Usuario no encontrado.");
                                    userId = Convert.ToInt32(res);
                                }

                                // 5) Comprobar si ya existe en watch_later
                                const string checkSql = @"
                                    SELECT COUNT(1)
                                      FROM dbo.watch_later
                                     WHERE id_user = @id_user
                                       AND id_book = @id_book";
                                int existCount;
                                using (var cmdCheck = new SqlCommand(checkSql, conn))
                                {
                                    cmdCheck.Parameters.AddWithValue("@id_user", userId);
                                    cmdCheck.Parameters.AddWithValue("@id_book", bookId);
                                    existCount = Convert.ToInt32(await cmdCheck.ExecuteScalarAsync());
                                }

                                if (existCount > 0)
                                {
                                    return new OkObjectResult("El libro ya está en tu lista de 'ver más tarde'.");
                                }

                                // 6) Insertar en watch_later
                                const string insertSql = @"
                                    INSERT INTO dbo.watch_later (
                                        id_user,
                                        id_book,
                                        created_at
                                    ) VALUES (
                                        @id_user,
                                        @id_book,
                                        SYSDATETIME()
                                    )";
                                using (var cmdInsert = new SqlCommand(insertSql, conn))
                                {
                                    cmdInsert.Parameters.AddWithValue("@id_user", userId);
                                    cmdInsert.Parameters.AddWithValue("@id_book", bookId);
                                    await cmdInsert.ExecuteNonQueryAsync();
                                }
                            }

                            return new OkObjectResult("Libro añadido a tu lista de 'ver más tarde' correctamente.");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al añadir libro a watch_later: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "searchbooks":
                    {
                        // 1) Validar que se reciba el parámetro 'accesstoken'.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        }

                        // Validar que el token sea correcto.
                        if (!IsTokenValid(accessToken))
                        {
                            return new UnauthorizedResult();
                        }

                        // 3) Leer y validar el término de búsqueda
                        string searchTerm = req.Query["query"];
                        if (string.IsNullOrWhiteSpace(searchTerm))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'query' con el texto a buscar.");
                        }

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // 4) Buscar en título o autor usando LIKE
                                string sql = @"
                                    SELECT id_book, title, published_date, author, file_path, description
                                    FROM dbo.book
                                    WHERE title    LIKE @pattern
                                       OR author   LIKE @pattern
                                    ORDER BY title";

                                using (SqlCommand cmd = new SqlCommand(sql, conn))
                                {
                                    string pattern = "%" + searchTerm + "%";
                                    cmd.Parameters.AddWithValue("@pattern", pattern);

                                    var results = new List<object>();
                                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                                    {
                                        while (await reader.ReadAsync())
                                        {
                                            results.Add(new
                                            {
                                                IdBook = reader.GetInt32(0),
                                                Title = reader.GetString(1),
                                                PublishedDate = reader.IsDBNull(2) ? (DateTime?)null : reader.GetDateTime(2),
                                                Author = reader.GetString(3),
                                                FilePath = reader.GetString(4),
                                                Description = reader.IsDBNull(5) ? "" : reader.GetString(5)
                                            });
                                        }
                                    }

                                    return new OkObjectResult(results);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error en searchbooks: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "getcategoriesbybook":
                    {
                          // 1) Validar que se reciba el parámetro 'accesstoken'.
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        }

                        // Validar que el token sea correcto.
                        if (!IsTokenValid(accessToken))
                        {
                            return new UnauthorizedResult();
                        }
                        // 3) Validar que se reciba 'bookId' y que sea un entero válido.
                        if (!int.TryParse(req.Query["bookId"], out int bookId))
                            return new BadRequestObjectResult("Debe proporcionar un 'bookId' válido.");

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // 4) Consulta para obtener las categorías del libro.
                                string query = @"
                                    SELECT c.id_category, c.name
                                    FROM category c
                                    INNER JOIN book_category bc ON c.id_category = bc.id_category
                                    WHERE bc.id_book = @bookId";

                                var categories = new List<object>();
                                using (SqlCommand cmd = new SqlCommand(query, conn))
                                {
                                    cmd.Parameters.AddWithValue("@bookId", bookId);

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
                                }

                                // 5) Retornar la lista de categorías en JSON.
                                return new OkObjectResult(categories);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener categorías para el libro {bookId}: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "getlikedbooks":
                    {
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        if (!IsTokenValid(accessToken))
                            return new UnauthorizedResult();

                        string username = GetUsernameFromToken(accessToken);
                        if (username == null)
                            return new UnauthorizedResult();

                        try
                        {
                            using var conn = new SqlConnection(_connectionString);
                            await conn.OpenAsync();

                            string sql = @"
                                SELECT b.id_book, b.title, b.published_date, b.author, b.file_path, b.description
                                FROM dbo.favorites f
                                INNER JOIN dbo.[User] u ON u.id_user = f.id_user
                                INNER JOIN dbo.book b ON b.id_book = f.id_book
                                WHERE u.Username = @username
                                ORDER BY f.created_at DESC";

                            var favs = new List<object>();
                            using (var cmd = new SqlCommand(sql, conn))
                            {
                                cmd.Parameters.AddWithValue("@username", username);
                                using var reader = await cmd.ExecuteReaderAsync();
                                while (await reader.ReadAsync())
                                {
                                    favs.Add(new
                                    {
                                        IdBook = reader.GetInt32(0),
                                        Title = reader.GetString(1),
                                        PublishedDate = reader.IsDBNull(2) ? (DateTime?)null : reader.GetDateTime(2),
                                        Author = reader.GetString(3),
                                        FilePath = reader.GetString(4),
                                        Description = reader.IsDBNull(5) ? "" : reader.GetString(5)
                                    });
                                }
                            }

                            return new OkObjectResult(favs);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener favoritos: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "getmylist":
                    {
                        // 1) Validar access token
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        if (!IsTokenValid(accessToken))
                            return new UnauthorizedResult();

                        // 2) Extraer username y luego id_user
                        string username = GetUsernameFromToken(accessToken);
                        if (username == null)
                            return new UnauthorizedResult();

                        try
                        {
                            using var conn = new SqlConnection(_connectionString);
                            await conn.OpenAsync();

                            // 3) Consulta: join watch_later con book para devolver los datos
                            string sql = @"
                                SELECT b.id_book, b.title, b.published_date, b.author, b.file_path, b.description
                                FROM dbo.watch_later wl
                                INNER JOIN dbo.[User] u ON u.id_user = wl.id_user
                                INNER JOIN dbo.book b ON b.id_book = wl.id_book
                                WHERE u.Username = @username
                                ORDER BY wl.created_at DESC";

                            var list = new List<object>();
                            using (var cmd = new SqlCommand(sql, conn))
                            {
                                cmd.Parameters.AddWithValue("@username", username);
                                using var reader = await cmd.ExecuteReaderAsync();
                                while (await reader.ReadAsync())
                                {
                                    list.Add(new
                                    {
                                        IdBook = reader.GetInt32(0),
                                        Title = reader.GetString(1),
                                        PublishedDate = reader.IsDBNull(2) ? (DateTime?)null : reader.GetDateTime(2),
                                        Author = reader.GetString(3),
                                        FilePath = reader.GetString(4),
                                        Description = reader.IsDBNull(5) ? "" : reader.GetString(5)
                                    });
                                }
                            }

                            return new OkObjectResult(list);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener Mi Lista: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "removetolist":
                    {
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        if (!IsTokenValid(accessToken))
                            return new UnauthorizedResult();

                        string username = GetUsernameFromToken(accessToken);
                        if (username == null)
                            return new UnauthorizedResult();
                        if (!int.TryParse(req.Query["bookId"], out int bookId))
                            return new BadRequestObjectResult("Parámetro 'bookId' inválido o ausente.");

                        try
                        {
                            using var conn = new SqlConnection(_connectionString);
                            await conn.OpenAsync();

                            // 1) Obtener id_user
                            int userId;
                            using (var cmdU = new SqlCommand("SELECT id_user FROM dbo.[User] WHERE Username = @username", conn))
                            {
                                cmdU.Parameters.AddWithValue("@username", username);
                                var res = await cmdU.ExecuteScalarAsync();
                                if (res == null) return new BadRequestObjectResult("Usuario no encontrado.");
                                userId = Convert.ToInt32(res);
                            }

                            // 2) Eliminar
                            const string delSql = @"
                                DELETE FROM dbo.watch_later
                                 WHERE id_user = @userId
                                   AND id_book = @bookId";
                            using var cmdDel = new SqlCommand(delSql, conn);
                            cmdDel.Parameters.AddWithValue("@userId", userId);
                            cmdDel.Parameters.AddWithValue("@bookId", bookId);
                            int rows = await cmdDel.ExecuteNonQueryAsync();

                            return new OkObjectResult(rows > 0
                                ? "Libro eliminado de Mi Lista."
                                : "El libro no se encontró en Mi Lista.");
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al quitar de Mi Lista: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }
                case "getbooksbyids":
                    {
                        // 1) Validar access token
                        string accessToken = req.Query["accesstoken"];
                        if (string.IsNullOrWhiteSpace(accessToken))
                            return new BadRequestObjectResult("Debe proporcionar el parámetro 'accesstoken'.");
                        if (!IsTokenValid(accessToken))
                            return new UnauthorizedResult();

                        // 2) Leer y deserializar lista de IDs del cuerpo JSON
                        string requestBody;
                        using (var reader = new StreamReader(req.Body))
                            requestBody = await reader.ReadToEndAsync();

                        List<int> ids;
                        try
                        {
                            ids = JsonSerializer.Deserialize<List<int>>(requestBody);
                        }
                        catch
                        {
                            return new BadRequestObjectResult("El cuerpo de la petición debe ser un JSON con una lista de enteros (IDs de libros).");
                        }

                        if (ids == null || ids.Count == 0)
                            return new BadRequestObjectResult("Debe proporcionar una lista de IDs de libros en el cuerpo de la petición.");

                        try
                        {
                            using (SqlConnection conn = new SqlConnection(_connectionString))
                            {
                                await conn.OpenAsync();

                                // Construir consulta con parámetros dinámicos para IN
                                var paramNames = new List<string>();
                                for (int i = 0; i < ids.Count; i++)
                                    paramNames.Add($"@id{i}");

                                string sql = $@"
                                    SELECT id_book, title, published_date, author, file_path, description
                                    FROM dbo.book
                                    WHERE id_book IN ({string.Join(",", paramNames)})";

                                var books = new List<object>();
                                using (SqlCommand cmd = new SqlCommand(sql, conn))
                                {
                                    for (int i = 0; i < ids.Count; i++)
                                        cmd.Parameters.AddWithValue(paramNames[i], ids[i]);

                                    using (SqlDataReader reader = await cmd.ExecuteReaderAsync())
                                    {
                                        while (await reader.ReadAsync())
                                        {
                                            books.Add(new
                                            {
                                                IdBook = reader.GetInt32(0),
                                                Title = reader.GetString(1),
                                                PublishedDate = reader.IsDBNull(2) ? (DateTime?)null : reader.GetDateTime(2),
                                                Author = reader.GetString(3),
                                                FilePath = reader.GetString(4),
                                                Description = reader.IsDBNull(5) ? string.Empty : reader.GetString(5)
                                            });
                                        }
                                    }
                                }

                                return new OkObjectResult(books);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al obtener libros por IDs: {ex.Message}");
                            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                        }
                    }

                case "createcheckoutsession":
                    {
                        try
                        {
                            var stripeKey = Environment.GetEnvironmentVariable("STRIPE_SECRET_KEY");
                            if (string.IsNullOrEmpty(stripeKey))
                            {
                                _logger.LogError("STRIPE_SECRET_KEY is not set.");
                                return new StatusCodeResult(500);
                            }

                            Stripe.StripeConfiguration.ApiKey = stripeKey;

                            var options = new Stripe.Checkout.SessionCreateOptions
                            {
                                PaymentMethodTypes = new List<string> { "card" },
                                LineItems = new List<Stripe.Checkout.SessionLineItemOptions>
                                {
                                    new Stripe.Checkout.SessionLineItemOptions
                                    {
                                        PriceData = new Stripe.Checkout.SessionLineItemPriceDataOptions
                                        {
                                            Currency = "usd",
                                            UnitAmount = 9900, // $99.00 en centavos
                                            ProductData = new Stripe.Checkout.SessionLineItemPriceDataProductDataOptions
                                            {
                                                Name = "Suscripción SmartRead"
                                            },
                                        },
                                        Quantity = 1,
                                    },
                                },
                                Mode = "payment",
                                SuccessUrl = "https://smartread.app/success",
                                CancelUrl = "https://smartread.app/cancel",
                            };

                            var service = new Stripe.Checkout.SessionService();
                            var session = await service.CreateAsync(options);

                            return new OkObjectResult(new
                            {
                                url = session.Url,
                                sessionId = session.Id   
                            });
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError($"Error al crear la sesión de Stripe: {ex.Message}");
                            return new StatusCodeResult(500);
                        }
                    }



                default:
                    return new BadRequestObjectResult("La acción especificada no es válida. Use 'login', 'register', 'sendcode', 'validatecode', 'validate', 'refreshtoken', 'getcategories' o 'getmorebooks'.");
            }
        }

        /// <summary>
        /// Genera un Access Token (JWT) con una expiración de 60 minutos.
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
        /// Genera un Refresh Token (JWT) con una expiración de 7 días.
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
        /// Valida el token (JWT) usando la misma clave secreta y parámetros de validación.
        /// Retorna true si el token es válido y no ha expirado; de lo contrario, false.
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

        private string GetUsernameFromToken(string token)
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
                // 1) Validar el token y obtener el ClaimsPrincipal
                var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                // 2) Intentar extraer el username de distintos claims
                string username = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                               ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                               ?? principal.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value
                               ?? principal.FindFirst(ClaimTypes.Name)?.Value;

                return string.IsNullOrEmpty(username) ? null : username;
            }
            catch
            {
                // Token inválido o expirado
                return null;
            }
        }
    }
}
