using Microsoft.EntityFrameworkCore;
using GraphQLWorkshop.Context; // Changé
using GraphQLWorkshop.Models;

namespace GraphQLWorkshop.Types;

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