using Microsoft.EntityFrameworkCore;
using GraphQLWorkshop.Context;
using GraphQLWorkshop.Models;
using System.Security.Claims;

namespace GraphQLWorkshop.Services;

public interface IAuthService
{
    Task<bool> HasPermissionAsync(ClaimsPrincipal user, string resource, string action);
    Task<IEnumerable<string>> GetUserPermissionsAsync(Guid userId);
}

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _context;
    
    public AuthService(ApplicationDbContext context)
    {
        _context = context;
    }
    
    public Task<bool> HasPermissionAsync(ClaimsPrincipal user, string resource, string action)
    {
        var permissionName = $"{resource}.{action}";
        var hasPermission = user.Claims.Any(c => c.Type == "permission" && c.Value == permissionName);
        return Task.FromResult(hasPermission);
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