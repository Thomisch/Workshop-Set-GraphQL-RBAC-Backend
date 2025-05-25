using Microsoft.EntityFrameworkCore;
using GraphQLWorkshop.Context;
using GraphQLWorkshop.Models;
using GraphQLWorkshop.Services;
using BCrypt.Net;
using System.Security.Claims;

namespace GraphQLWorkshop.Mutations;

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

    // Enlever [Authorize(Policy = "AdminOnly")] temporairement
    public async Task<User> DeactivateUserAsync(
        Guid userId,
        [Service] ApplicationDbContext context)
    {
        var user = await context.Users.FindAsync(userId);
        if (user == null)
            throw new GraphQLException("Utilisateur non trouvé");

        user.IsActive = false;
        await context.SaveChangesAsync();

        return user;
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
    
    public async Task<User> AssignRoleToUserAsync(
        Guid userId,
        Guid roleId,
        ClaimsPrincipal claimsPrincipal,
        [Service] ApplicationDbContext context)
    {
        if (!claimsPrincipal.IsInRole("Admin"))
        {
            throw new GraphQLException("Accès refusé : rôle Admin requis");
        }

        var user = await context.Users.FindAsync(userId);
        if (user == null)
            throw new GraphQLException("Utilisateur non trouvé");

        var role = await context.Roles.FindAsync(roleId);
        if (role == null)
            throw new GraphQLException("Rôle non trouvé");

        // Vérifier si l'association existe déjà
        var existingUserRole = await context.UserRoles
            .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId);

        if (existingUserRole == null)
        {
            context.UserRoles.Add(new UserRole { UserId = userId, RoleId = roleId });
            await context.SaveChangesAsync();
        }

        return await context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstAsync(u => u.Id == userId);
    }

    // Mutation de test pour créer un utilisateur avec un rôle spécifique
    public async Task<AuthPayload> CreateTestUserAsync(
        string email,
        string roleName,
        ClaimsPrincipal claimsPrincipal,
        [Service] ApplicationDbContext context,
        [Service] IJwtService jwtService)
    {
        if (!claimsPrincipal.IsInRole("Admin"))
        {
            throw new GraphQLException("Accès refusé : rôle Admin requis");
        }

        if (await context.Users.AnyAsync(u => u.Email == email))
        {
            throw new GraphQLException("Un utilisateur avec cet email existe déjà");
        }

        var role = await context.Roles.FirstOrDefaultAsync(r => r.Name == roleName);
        if (role == null)
        {
            throw new GraphQLException($"Rôle '{roleName}' non trouvé");
        }

        var user = new User
        {
            Email = email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("TestPassword123!"),
            FirstName = "Test",
            LastName = "User"
        };

        context.Users.Add(user);
        context.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });
        await context.SaveChangesAsync();

        var permissions = await GetUserPermissions(user.Id, context);
        var token = jwtService.GenerateToken(user.Id, user.Email, new[] { roleName }, permissions);

        return new AuthPayload(token, user);
    }
}

public record RegisterInput(string Email, string Password, string? FirstName, string? LastName);
public record LoginInput(string Email, string Password);
public record AuthPayload(string Token, User User);