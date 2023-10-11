using Microsoft.AspNetCore.Mvc;
using Npgsql;
using System.Security.Cryptography;
using System.Text;
using API_JWT.Model;
using System.Net.Mail;
using System.Net;
using API_JWT.Utils;

namespace BetBuilderAPI.Controllers
{
    [Route("/")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly string _jwtSecret;

        public LoginController(IConfiguration configuration)
        {
            _configuration = configuration;
            _jwtSecret = _configuration.GetValue<string>("AppSettings:JwtSecret");

            if (string.IsNullOrEmpty(_jwtSecret))
            {
                throw new ArgumentException(
                    "A chave secreta não pode ser nula ou vazia.",
                    nameof(_jwtSecret)
                );
            }
        }

        [HttpPost("RegistrarUsuario")]
        public async Task<IActionResult> RegisterUser([FromBody] RegistroModel registroModel)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("BetBuilder");

                using (var connection = new NpgsqlConnection(connectionString))
                {
                    await connection.OpenAsync();

                    string query =
                        $"SELECT COUNT(*) as total FROM Cad_Usuario WHERE Email = '{registroModel.Email}'";
                    using (var command = new NpgsqlCommand(query, connection))
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (await reader.ReadAsync() && Convert.ToInt32(reader["total"]) > 0)
                        {
                            return BadRequest(new { message = "Email já está cadastrado." });
                        }
                    }

                    using (var sha256 = SHA256.Create())
                    {
                        var bytes = Encoding.UTF8.GetBytes(registroModel.Senha);
                        var hash = sha256.ComputeHash(bytes);
                        registroModel.Senha = Convert.ToBase64String(hash);
                    }

                    query =
                        $"INSERT INTO Cad_Usuario (Email, Nome, Senha, Telefone) VALUES ('{registroModel.Email}', '{registroModel.Nome}', '{registroModel.Senha}','{registroModel.Telefone}')";
                    using (var command = new NpgsqlCommand(query, connection))
                    {
                        await command.ExecuteNonQueryAsync();
                    }

                    return Ok(new { message = "Usuário registrado com sucesso." });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = $"Erro ao registrar usuário: {ex.Message}" });
            }
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserModel userModel)
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("BetBuilder");

                using (var connection = new NpgsqlConnection(connectionString))
                {
                    await connection.OpenAsync();

                    string query = $"SELECT * FROM Cad_Usuario WHERE Email = '{userModel.Email}' ";
                    using (var command = new NpgsqlCommand(query, connection))
                    using (var reader = await command.ExecuteReaderAsync())
                    {
                        if (!await reader.ReadAsync())
                        {
                            return Unauthorized(new { message = "E-mail ou senha inválidos." });
                        }

                        var passwordHash = reader["Senha"] as string;
                        if (string.IsNullOrEmpty(passwordHash))
                        {
                            return Unauthorized(new { message = "E-mail ou senha inválidos." });
                        }

                        var email = (string)reader["Email"];
                        var wizardBool = (int)reader["WizardBool"];
                        var Nome = (string)reader["Nome"];
                        var Telefone = (string)reader["Telefone"];



                        var bytes = Encoding.UTF8.GetBytes(userModel.Senha);
                        using (var sha256 = SHA256.Create())
                        {
                            var hash = sha256.ComputeHash(bytes);
                            var passwordHashInput = Convert.ToBase64String(hash);

                            if (passwordHash != passwordHashInput)
                            {
                                return Unauthorized(new { message = "Senha inválida." });
                            }
                        }

                        var login = new UserModel
                        {
                            Id = (int)reader["Id"],
                            Email = email,
                            Nome = (string)reader["Nome"]
                        };
                        var token = JwtUtils.GenerateJwt(login, _jwtSecret);

                        return Ok(new { message = "Login efetuado com sucesso.", token, email, wizardBool, Nome, Telefone });
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(
                    StatusCodes.Status500InternalServerError,
                    new
                    {
                        message = "Ocorreu um erro ao processar a solicitação.",
                        error = ex.ToString()
                    }
                );
            }
        }


        [HttpPost("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(
            [FromBody] ForgotPasswordModel model
        )
        {
            try
            {
                string connectionString = _configuration.GetConnectionString("BetBuilder");

                using (var connection = new NpgsqlConnection(connectionString))
                {
                    await connection.OpenAsync();

                    string query =
                        "SELECT * FROM Cad_Usuario WHERE Email = @Email ";
                    using (var command = new NpgsqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@Email", model.Email);

                        using (var reader = await command.ExecuteReaderAsync())
                        {
                            if (!await reader.ReadAsync())
                            {
                                return BadRequest(new { message = "E-mail não encontrado." });
                            }

                            var loginModel = new UserModel { Email = model.Email };
                            var resetToken = JwtUtils.GenerateResetPasswordToken(
                                loginModel.Email,
                                _jwtSecret
                            );

                            string resetLink =
                                $"https://suaurl.com.br/resetpassword=/{resetToken}";

                            var smtpClient = new SmtpClient("smtp.gmail.com", 465);
                            smtpClient.DeliveryMethod = SmtpDeliveryMethod.Network;
                            smtpClient.EnableSsl = true;
                            smtpClient.Credentials = new NetworkCredential(
                                "XXXX@GMAIL.COM",
                                "XXXXXXX"
                            );

                            var mailMessage = new MailMessage();
                            mailMessage.From = new MailAddress("xxx@gmail.com");
                            mailMessage.To.Add(model.Email);
                            mailMessage.Subject = "Redefinição de senha";
                            if (!string.IsNullOrEmpty(resetLink))
                            {
                                string emailBody =
                                    @"
    <html>
    <head>
        <style>
            /* Estilos CSS para formatar o e-mail */
            /* ... */
        </style>
    </head>
    <body>
        <div style=""background-color: #ffffff; padding: 20px;"">
            <div style=""max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;"">
                <h1 style=""color: #000000; font-size: 24px; font-weight: bold; margin-bottom: 20px;"">Redefinição de Senha</h1>
                <p style=""color: #000000; font-size: 16px; margin-bottom: 30px;"">Olá,</p>
                <p style=""color: #000000; font-size: 16px; margin-bottom: 30px;"">Você solicitou a redefinição de senha para sua conta.</p>
                <p>Clique <a href="""
                                    + resetLink
                                    + @""">aqui</a> para criar uma nova senha.</p>
                <p style=""color: #000000; font-size: 16px; margin-bottom: 10px;"">Se você não solicitou a redefinição de senha, ignore este e-mail.</p>
                <p style=""color: #000000; font-size: 14px; margin-bottom: 10px;"">Obrigado,</p>
                <p style=""color: #000000; font-size: 14px; font-weight: bold; margin-bottom: 0;"">Equipe Suporte</p>
                <p style=""color: #000000; font-size: 14px;"">Caso acredite que estejam tentando invadir sua conta, entre em contato com o suporte.</p>
            </div>
        </div>
    </body>
    </html>
";

                                mailMessage.Body = emailBody;
                                mailMessage.IsBodyHtml = true;
                            }

                            await smtpClient.SendMailAsync(mailMessage);

                            return Ok(
                                new
                                {
                                    message = "Um e-mail com instruções para redefinir sua senha foi enviado."
                                }
                            );
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                return StatusCode(
                    StatusCodes.Status500InternalServerError,
                    new
                    {
                        message = "Ocorreu um erro ao processar a solicitação.",
                        error = ex.ToString()
                    }
                );
            }
        }
    }
}


