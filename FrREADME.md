# Workshop GraphQL Backend - C# .NET avec HotChocolate & PostgreSQL

Ce workshop vous guide dans la création d'un backend GraphQL complet avec authentification JWT et système RBAC (Role-Based Access Control).

## 🎯 Objectifs pédagogiques

- Créer un backend GraphQL avec HotChocolate
- Implémenter l'authentification JWT
- Mettre en place un système RBAC
- Intégrer PostgreSQL avec Entity Framework Core
- Créer des mutations d'authentification sécurisées

## 📋 Prérequis

- .NET 8 SDK
- Docker (pour PostgreSQL)
- IDE (Visual Studio Code ou Visual Studio)
- Connaissances de base en C# et SQL

## 🚀 Étape 1 : Configuration de l'environnement

### 1.1 Base de données PostgreSQL

Créez le fichier [`init-scripts/init.sql`](init-scripts/init.sql) :

```sql
-- Création de la base de données
CREATE DATABASE workshop_graphql;

-- Connexion à la base
\c workshop_graphql;

-- Table des utilisateurs
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des rôles
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des permissions
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table de liaison utilisateur-rôle
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- Table de liaison rôle-permission
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Données de test
INSERT INTO roles (id, name, description) VALUES
    ('11111111-1111-1111-1111-111111111111', 'Admin', 'Administrateur système'),
    ('22222222-2222-2222-2222-222222222222', 'User', 'Utilisateur standard'),
    ('33333333-3333-3333-3333-333333333333', 'Manager', 'Gestionnaire');

INSERT INTO permissions (id, name, description, resource, action) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'users.read', 'Lire les utilisateurs', 'users', 'read'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'users.write', 'Modifier les utilisateurs', 'users', 'write'),
    ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'users.delete', 'Supprimer les utilisateurs', 'users', 'delete'),
    ('dddddddd-dddd-dddd-dddd-dddddddddddd', 'roles.manage', 'Gérer les rôles', 'roles', 'manage');

-- Attribution des permissions aux rôles
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    ('11111111-1111-1111-1111-111111111111', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    ('11111111-1111-1111-1111-111111111111', 'cccccccc-cccc-cccc-cccc-cccccccccccc'),
    ('11111111-1111-1111-1111-111111111111', 'dddddddd-dddd-dddd-dddd-dddddddddddd'),
    ('22222222-2222-2222-2222-222222222222', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    ('33333333-3333-3333-3333-333333333333', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    ('33333333-3333-3333-3333-333333333333', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
```

### 1.2 Initialisation du projet .NET

```bash
# Création du projet
dotnet new webapi -n GraphQLWorkshop
cd GraphQLWorkshop

# Ajout des packages NuGet
dotnet add package HotChocolate.AspNetCore
dotnet add package HotChocolate.Data
dotnet add package HotChocolate.Data.EntityFramework
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package BCrypt.Net-Next
dotnet add package System.IdentityModel.Tokens.Jwt
```

## 📊 Étape 2 : Modèles de données et DbContext

### 2.1 Modèles RBAC

Créez [`GraphQLWorkshop/Models/RbacModel.cs`](GraphQLWorkshop/Models/RbacModel.cs) :

```csharp
using System.ComponentModel.DataAnnotations;

namespace GraphQLWorkshop.Models;

public class User
{
    public Guid Id { get; set; }
    
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    public string PasswordHash { get; set; } = string.Empty;
    
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    
    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
}

public class Role
{
    public Guid Id { get; set; }
    
    [Required]
    public string Name { get; set; } = string.Empty;
    
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

public class Permission
{
    public Guid Id { get; set; }
    
    [Required]
    public string Name { get; set; } = string.Empty;
    
    public string? Description { get; set; }
    
    [Required]
    public string Resource { get; set; } = string.Empty;
    
    [Required]
    public string Action { get; set; } = string.Empty;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

public class UserRole
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;
    
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
}

public class RolePermission
{
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;
    
    public Guid PermissionId { get; set; }
    public Permission Permission { get; set; } = null!;
    
    public DateTime GrantedAt { get; set; } = DateTime.UtcNow;
}
```

### 2.2 DbContext

Créez [`GraphQLWorkshop/Context/DbContext.cs`](GraphQLWorkshop/Context/DbContext.cs) :

```csharp
using Microsoft.EntityFrameworkCore;
using GraphQLWorkshop.Models;

namespace GraphQLWorkshop.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
    
    public DbSet<User> Users { get; set; }
    public DbSet<Role> Roles { get; set; }
    public DbSet<Permission> Permissions { get; set; }
    public DbSet<UserRole> UserRoles { get; set; }
    public DbSet<RolePermission> RolePermissions { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configuration UserRole
        modelBuilder.Entity<UserRole>()
            .HasKey(ur => new { ur.UserId, ur.RoleId });
            
        modelBuilder.Entity<UserRole>()
            .HasOne(ur => ur.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(ur => ur.UserId);
            
        modelBuilder.Entity<UserRole>()
            .HasOne(ur => ur.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(ur => ur.RoleId);
        
        // Configuration RolePermission
        modelBuilder.Entity<RolePermission>()
            .HasKey(rp => new { rp.RoleId, rp.PermissionId });
            
        modelBuilder.Entity<RolePermission>()
            .HasOne(rp => rp.Role)
            .WithMany(r => r.RolePermissions)
            .HasForeignKey(rp => rp.RoleId);
            
        modelBuilder.Entity<RolePermission>()
            .HasOne(rp => rp.Permission)
            .WithMany(p => p.RolePermissions)
            .HasForeignKey(rp => rp.PermissionId);
    }
}
```

## 🔐 Étape 3 : Services d'authentification

### 3.1 Service JWT

Créez [`GraphQLWorkshop/Services/JwtService.cs`](GraphQLWorkshop/Services/JwtService.cs) :

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace GraphQLWorkshop.Services;

public interface IJwtService
{
    string GenerateToken(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> permissions);
    ClaimsPrincipal? ValidateToken(string token);
}

public class JwtService : IJwtService
{
    private readonly IConfiguration _configuration;
    
    public JwtService(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public string GenerateToken(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> permissions)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Email, email)
        };
        
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
        claims.AddRange(permissions.Select(permission => new Claim("permission", permission)));
        
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddHours(24),
            signingCredentials: credentials
        );
        
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    public ClaimsPrincipal? ValidateToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);
            
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
            
            return tokenHandler.ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            return null;
        }
    }
}
```

### 3.2 Service d'autorisation RBAC

Créez [`GraphQLWorkshop/Services/AuthorizationService.cs`](GraphQLWorkshop/Services/AuthorizationService.cs) :

```csharp
using Microsoft.EntityFrameworkCore;
using GraphQLWorkshop.Data;
using System.Security.Claims;

namespace GraphQLWorkshop.Services;

public interface IAuthorizationService
{
    Task<bool> HasPermissionAsync(ClaimsPrincipal user, string resource, string action);
    Task<IEnumerable<string>> GetUserPermissionsAsync(Guid userId);
}

public class AuthorizationService : IAuthorizationService
{
    private readonly ApplicationDbContext _context;
    
    public AuthorizationService(ApplicationDbContext context)
    {
        _context = context;
    }
    
    public async Task<bool> HasPermissionAsync(ClaimsPrincipal user, string resource, string action)
    {
        var permissionName = $"{resource}.{action}";
        return user.Claims.Any(c => c.Type == "permission" && c.Value == permissionName);
    }
    
    public async Task<IEnumerable<string>> GetUserPermissionsAsync(Guid userId)
    {
        return await _context.Users
            .Where(u => u.Id == userId)
            .SelectMany(u => u.UserRoles)
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToListAsync();
    }
}
```

## 🎯 Étape 4 : GraphQL avec HotChocolate

### 4.1 Types GraphQL

Créez [`GraphQLWorkshop/Types/UserType.cs`](GraphQLWorkshop/Types/UserType.cs) :

```csharp
using GraphQLWorkshop.Models;
using GraphQLWorkshop.Data;
using Microsoft.EntityFrameworkCore;

namespace GraphQLWorkshop.GraphQL.Types;

public class UserType : ObjectType<User>
{
    protected override void Configure(IObjectTypeDescriptor<User> descriptor)
    {
        descriptor.Field(u => u.PasswordHash).Ignore();
        
        descriptor.Field(u => u.UserRoles)
            .ResolveWith<UserResolvers>(r => r.GetRoles(default!, default!));
    }
}

public class UserResolvers
{
    public async Task<IEnumerable<Role>> GetRoles([Parent] User user, ApplicationDbContext context)
    {
        return await context.UserRoles
            .Where(ur => ur.UserId == user.Id)
            .Select(ur => ur.Role)
            .ToListAsync();
    }
}
```

### 4.2 Mutations d'authentification

Créez [`GraphQLWorkshop/Mutations/AuthMutation.cs`](GraphQLWorkshop/Mutations/AuthMutation.cs) :

```csharp
using HotChocolate.Authorization;
using Microsoft.EntityFrameworkCore;
using GraphQLWorkshop.Data;
using GraphQLWorkshop.Models;
using GraphQLWorkshop.Services;
using BCrypt.Net;

namespace GraphQLWorkshop.GraphQL.Mutations;

[ExtendObjectType("Mutation")]
public class AuthMutation
{
    public async Task<AuthPayload> RegisterAsync(
        RegisterInput input,
        [Service] ApplicationDbContext context,
        [Service] IJwtService jwtService)
    {
        if (await context.Users.AnyAsync(u => u.Email == input.Email))
        {
            throw new GraphQLException("Un utilisateur avec cet email existe déjà");
        }
        
        var user = new User
        {
            Email = input.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(input.Password),
            FirstName = input.FirstName,
            LastName = input.LastName
        };
        
        context.Users.Add(user);
        
        // Assigner le rôle "User" par défaut
        var userRole = await context.Roles.FirstAsync(r => r.Name == "User");
        context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = userRole.Id });
        
        await context.SaveChangesAsync();
        
        var permissions = await GetUserPermissions(user.Id, context);
        var token = jwtService.GenerateToken(user.Id, user.Email, new[] { "User" }, permissions);
        
        return new AuthPayload(token, user);
    }
    
    public async Task<AuthPayload> LoginAsync(
        LoginInput input,
        [Service] ApplicationDbContext context,
        [Service] IJwtService jwtService)
    {
        var user = await context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Email == input.Email);
            
        if (user == null || !BCrypt.Net.BCrypt.Verify(input.Password, user.PasswordHash))
        {
            throw new GraphQLException("Email ou mot de passe incorrect");
        }
        
        if (!user.IsActive)
        {
            throw new GraphQLException("Compte désactivé");
        }
        
        var roles = user.UserRoles.Select(ur => ur.Role.Name);
        var permissions = await GetUserPermissions(user.Id, context);
        var token = jwtService.GenerateToken(user.Id, user.Email, roles, permissions);
        
        return new AuthPayload(token, user);
    }
    
    private async Task<IEnumerable<string>> GetUserPermissions(Guid userId, ApplicationDbContext context)
    {
        return await context.UserRoles
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.Permission.Name)
            .Distinct()
            .ToListAsync();
    }
}

public record RegisterInput(string Email, string Password, string? FirstName, string? LastName);
public record LoginInput(string Email, string Password);
public record AuthPayload(string Token, User User);
```

## ⚙️ Étape 5 : Configuration du projet

### 5.1 Program.cs

Modifiez [`GraphQLWorkshop/Program.cs`](GraphQLWorkshop/Program.cs) :

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using GraphQLWorkshop.Data;
using GraphQLWorkshop.Services;
using GraphQLWorkshop.GraphQL.Mutations;
using GraphQLWorkshop.GraphQL.Types;

var builder = WebApplication.CreateBuilder(args);

// Configuration Entity Framework
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Services
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IAuthorizationService, AuthorizationService>();

// Configuration JWT
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

// Configuration GraphQL
builder.Services
    .AddGraphQLServer()
    .AddQueryType(q => q.Name("Query"))
    .AddMutationType(m => m.Name("Mutation"))
    .AddType<UserType>()
    .AddTypeExtension<AuthMutation>()
    .AddAuthentication()
    .AddAuthorization()
    .AddFiltering()
    .AddSorting();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGraphQL();

app.Run();
```

### 5.2 Configuration

Modifiez [`GraphQLWorkshop/appsettings.json`](GraphQLWorkshop/appsettings.json) :

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=workshop_graphql;Username=postgres;Password=mypassword"
  },
  "Jwt": {
    "Key": "VotreCleSecrete32CaracteresMinimum!",
    "Issuer": "GraphQLWorkshop",
    "Audience": "GraphQLWorkshopUsers"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

## 🧪 Étape 6 : Tests et démarrage

### 6.1 Démarrage des services

```bash
# Démarrer PostgreSQL
./launchPostgresDocker.sh

# Démarrer l'application
dotnet run
```

### 6.2 Test avec GraphQL Playground

Accédez à `https://localhost:5001/graphql` pour tester :

**Mutation d'inscription :**
```graphql
mutation {
  register(input: {
    email: "admin@example.com"
    password: "Password123!"
    firstName: "Admin"
    lastName: "User"
  }) {
    token
    user {
      id
      email
      firstName
      lastName
    }
  }
}
```

**Mutation de connexion :**
```graphql
mutation {
  login(input: {
    email: "admin@example.com"
    password: "Password123!"
  }) {
    token
    user {
      id
      email
    }
  }
}
```

## 📝 Points clés à retenir

1. **Architecture RBAC** : Séparation claire entre utilisateurs, rôles et permissions
2. **Sécurité JWT** : Tokens signés avec claims personnalisés pour les permissions
3. **GraphQL** : Mutations sécurisées avec validation et gestion d'erreurs
4. **Entity Framework** : Relations many-to-many avec tables de liaison
5. **HotChocolate** : Configuration GraphQL avec types personnalisés et resolvers

## 🎓 Exercices complémentaires

1. Ajouter une query pour récupérer les utilisateurs avec filtrage par rôle
2. Implémenter une mutation pour modifier les permissions d'un utilisateur
3. Ajouter la validation des mots de passe complexes
4. Créer des directives d'autorisation personnalisées
5. Implémenter la pagination sur les queries

---

**Durée estimée :** 3-4 heures  
**Niveau :** Intermédiaire à Avancé