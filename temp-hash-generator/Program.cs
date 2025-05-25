using BCrypt.Net;

Console.WriteLine("Génération des hashes pour Password123!");
Console.WriteLine();

var password = "Password123!";

for (int i = 0; i < 3; i++)
{
    var hash = BCrypt.Net.BCrypt.HashPassword(password);
    Console.WriteLine($"Hash {i + 1}: {hash}");
}

// Vérification
var testHash = BCrypt.Net.BCrypt.HashPassword(password);
var isValid = BCrypt.Net.BCrypt.Verify(password, testHash);
Console.WriteLine($"\nVérification: {isValid}");