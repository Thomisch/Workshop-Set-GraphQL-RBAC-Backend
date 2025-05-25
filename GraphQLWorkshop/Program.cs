using Microsoft.EntityFrameworkCore;
using GraphQL.Server.Ui.Playground;
using GraphQLWorkshop.Context;
using GraphQLWorkshop.Services;
using GraphQLWorkshop.Mutations;
using GraphQLWorkshop.Types;
using GraphQLWorkshop.Query;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
// Configuration Entity Framework
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Services
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IAuthService, AuthService>();

// Configuration GraphQL simple
builder.Services
    .AddGraphQLServer()
    .AddQueryType<Query>()
    .AddMutationType<Mutation>()
    .AddTypeExtension<AuthMutation>()
    .AddType<UserType>()
    .AddAuthorization()
    .AddFiltering()
    .AddSorting();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGraphQL();

app.Run();