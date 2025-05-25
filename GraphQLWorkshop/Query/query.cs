using HotChocolate.Authorization;
using Microsoft.EntityFrameworkCore;
using GraphQLWorkshop.Context;
using GraphQLWorkshop.Models;
using GraphQLWorkshop.Services;
using System.Security.Claims;

namespace GraphQLWorkshop.Query;

public class Query
{
    // Query publique - pas d'autorisation requise
    public string GetVersion() => "1.0.0";
    
    public string GetStatus() => "API is running";

    // Query qui nécessite d'être connecté
    [Authorize]
    public async Task<User?> GetMeAsync(
        ClaimsPrincipal claimsPrincipal,
        [Service] ApplicationDbContext context)
    {
        var userIdClaim = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userIdClaim == null || !Guid.TryParse(userIdClaim, out var userId))
            return null;

        return await context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    // Query pour lire les utilisateurs - nécessite permission users.read
    public async Task<IEnumerable<User>> GetUsersAsync(
        ClaimsPrincipal claimsPrincipal,
        [Service] ApplicationDbContext context,
        [Service] IAuthService authService)
    {
        // Vérifier la permission
        if (!await authService.HasPermissionAsync(claimsPrincipal, "users", "read"))
        {
            throw new GraphQLException("Permission refusée : users.read requise");
        }

        return await context.Users
            .Where(u => u.IsActive)
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .ToListAsync();
    }

    // Query pour obtenir un utilisateur par ID - nécessite permission users.read
    public async Task<User?> GetUserByIdAsync(
        Guid userId,
        ClaimsPrincipal claimsPrincipal,
        [Service] ApplicationDbContext context,
        [Service] IAuthService authService)
    {
        if (!await authService.HasPermissionAsync(claimsPrincipal, "users", "read"))
        {
            throw new GraphQLException("Permission refusée : users.read requise");
        }

        return await context.Users
            .Include(u => u.UserRoles)
            .ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.Id == userId);
    }

    // Query pour lister les rôles - nécessite permission roles.manage
    public async Task<IEnumerable<Role>> GetRolesAsync(
        ClaimsPrincipal claimsPrincipal,
        [Service] ApplicationDbContext context,
        [Service] IAuthService authService)
    {
        if (!await authService.HasPermissionAsync(claimsPrincipal, "roles", "manage"))
        {
            throw new GraphQLException("Permission refusée : roles.manage requise");
        }

        return await context.Roles
            .Include(r => r.RolePermissions)
            .ThenInclude(rp => rp.Permission)
            .ToListAsync();
    }

    // Query pour obtenir ses propres permissions
    [Authorize]
    public async Task<IEnumerable<string>> GetMyPermissionsAsync(
        ClaimsPrincipal claimsPrincipal,
        [Service] IAuthService authService)
    {
        var userIdClaim = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userIdClaim == null || !Guid.TryParse(userIdClaim, out var userId))
            return new List<string>();

        return await authService.GetUserPermissionsAsync(userId);
    }

    // Query pour tester les permissions (utile pour debug)
    [Authorize]
    public async Task<PermissionCheckResult> CheckPermissionAsync(
        string resource,
        string action,
        ClaimsPrincipal claimsPrincipal,
        [Service] IAuthService authService)
    {
        var hasPermission = await authService.HasPermissionAsync(claimsPrincipal, resource, action);
        var userEmail = claimsPrincipal.FindFirst(ClaimTypes.Email)?.Value ?? "Unknown";
        
        return new PermissionCheckResult
        {
            User = userEmail,
            Resource = resource,
            Action = action,
            HasPermission = hasPermission,
            RequiredPermission = $"{resource}.{action}"
        };
    }

    // Query pour obtenir les statistiques (Admin seulement)
    public async Task<AdminStats> GetAdminStatsAsync(
        ClaimsPrincipal claimsPrincipal,
        [Service] ApplicationDbContext context)
    {
        // Vérifier le rôle Admin
        if (!claimsPrincipal.IsInRole("Admin"))
        {
            throw new GraphQLException("Accès refusé : rôle Admin requis");
        }

        var totalUsers = await context.Users.CountAsync();
        var activeUsers = await context.Users.CountAsync(u => u.IsActive);
        var totalRoles = await context.Roles.CountAsync();
        var totalPermissions = await context.Permissions.CountAsync();

        return new AdminStats
        {
            TotalUsers = totalUsers,
            ActiveUsers = activeUsers,
            InactiveUsers = totalUsers - activeUsers,
            TotalRoles = totalRoles,
            TotalPermissions = totalPermissions
        };
    }
}

// Types de retour pour les queries
public class PermissionCheckResult
{
    public string User { get; set; } = string.Empty;
    public string Resource { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public bool HasPermission { get; set; }
    public string RequiredPermission { get; set; } = string.Empty;
}

public class AdminStats
{
    public int TotalUsers { get; set; }
    public int ActiveUsers { get; set; }
    public int InactiveUsers { get; set; }
    public int TotalRoles { get; set; }
    public int TotalPermissions { get; set; }
}