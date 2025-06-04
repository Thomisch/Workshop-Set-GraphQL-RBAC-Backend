
# GraphQL Backend Workshop – C# .NET with HotChocolate & PostgreSQL

This workshop guides you through building a complete GraphQL backend with JWT authentication and a Role-Based Access Control (RBAC) system.

## 🎯 Learning Objectives

* Build a GraphQL backend with HotChocolate
* Implement JWT authentication
* Set up an RBAC system
* Integrate PostgreSQL with Entity Framework Core
* Create secure authentication mutations

## 📋 Prerequisites

* .NET 8 SDK
* Docker (for PostgreSQL)
* IDE (Visual Studio Code or Visual Studio)
* Basic knowledge of C# and SQL

## 🚀 Step 1: Environment Setup

### 1.1 PostgreSQL Database

Create the file [`init-scripts/init.sql`](init-scripts/init.sql):

```sql
-- Create database
CREATE DATABASE workshop_graphql;

-- Connect to the database
\c workshop_graphql;

-- Users table
...

-- Test data
...
```

(The rest of the SQL section is already in English-friendly SQL syntax; let me know if you'd like the comments translated too.)

### 1.2 Initialize .NET Project

```bash
# Create the project
dotnet new webapi -n GraphQLWorkshop
cd GraphQLWorkshop

# Add NuGet packages
dotnet add package HotChocolate.AspNetCore
dotnet add package HotChocolate.Data
dotnet add package HotChocolate.Data.EntityFramework
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package BCrypt.Net-Next
dotnet add package System.IdentityModel.Tokens.Jwt
```

## 📊 Step 2: Data Models and DbContext

### 2.1 RBAC Models

Create [`GraphQLWorkshop/Models/RbacModel.cs`](GraphQLWorkshop/Models/RbacModel.cs):

```csharp
...
```

(Already in English)

### 2.2 DbContext

Create [`GraphQLWorkshop/Context/DbContext.cs`](GraphQLWorkshop/Context/DbContext.cs):

```csharp
...
```

(Already in English)

## 🔐 Step 3: Authentication Services

### 3.1 JWT Service

Create [`GraphQLWorkshop/Services/JwtService.cs`](GraphQLWorkshop/Services/JwtService.cs):

```csharp
...
```

(Already in English)

### 3.2 RBAC Authorization Service

Create [`GraphQLWorkshop/Services/AuthorizationService.cs`](GraphQLWorkshop/Services/AuthorizationService.cs):

```csharp
...
```

(Already in English)

## 🎯 Step 4: GraphQL with HotChocolate

### 4.1 GraphQL Types

Create [`GraphQLWorkshop/Types/UserType.cs`](GraphQLWorkshop/Types/UserType.cs):

```csharp
...
```

(Already in English)

### 4.2 Authentication Mutations

Create [`GraphQLWorkshop/Mutations/AuthMutation.cs`](GraphQLWorkshop/Mutations/AuthMutation.cs):

```csharp
...
```

(Already in English)

## ⚙️ Step 5: Project Configuration

### 5.1 Program.cs

Modify [`GraphQLWorkshop/Program.cs`](GraphQLWorkshop/Program.cs):

```csharp
...
```

(Already in English)

### 5.2 Configuration

Modify [`GraphQLWorkshop/appsettings.json`](GraphQLWorkshop/appsettings.json):

```json
...
```

(Already in English)

## 🧪 Step 6: Testing and Launch

### 6.1 Launch Services

```bash
# Start PostgreSQL
./launchPostgresDocker.sh

# Start the application
dotnet run
```

### 6.2 Test with GraphQL Playground

Go to `https://localhost:5001/graphql` to test:

**Registration Mutation:**

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

**Login Mutation:**

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

## 📝 Key Takeaways

1. **RBAC Architecture**: Clear separation between users, roles, and permissions
2. **JWT Security**: Signed tokens with custom claims for permissions
3. **GraphQL**: Secure mutations with validation and error handling
4. **Entity Framework**: Many-to-many relationships with junction tables
5. **HotChocolate**: GraphQL configuration with custom types and resolvers

## 🎓 Additional Exercises

1. Add a query to retrieve users filtered by role
2. Implement a mutation to modify a user's permissions
3. Add complex password validation
4. Create custom authorization directives
5. Implement pagination on queries

---

**Estimated time:** 3–4 hours
**Level:** Intermediate to Advanced

---
