using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MySqlX.XDevAPI;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:key"]!)),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
    };
});


builder.Services.AddAuthentication();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();
IConfiguration configuration = app.Configuration;
IWebHostEnvironment environment = app.Environment;

app.MapControllers();


GuardianService.Util.Guardian.InitializeAppSettings();

//test below
//GuardianService.TEST.LOCAL_DEBUG.SHOW_GUARDIAN_CONFIGS();
//GuardianService.Util.Guardian.RunAppConnectionCheckList();
// GuardianService.Util.Data.AddOauthClient(); //only use when need add new client
//GuardianService.TEST.LOCAL_DEBUG.VALIDATE_SAMPLE_OAUTH_CLIENT();
//await GuardianService.TEST.LOCAL_DEBUG.GET_JWT();
//await GuardianService.Services.Auth.getAccessToken("77b177aa3835477cb709b7b6b3322c71");
//await GuardianService.TEST.LOCAL_DEBUG.GetAccessToken();
//await GuardianService.TEST.LOCAL_DEBUG.GetRefreshToken();

app.Run();
