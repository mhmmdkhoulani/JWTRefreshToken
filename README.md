# ASP.NET Web API with JWT and Refresh Token

This repository contains an ASP.NET Web API project that implements JWT (JSON Web Token) authentication with a secure refresh token mechanism. The project uses SQL Server as the database and Entity Framework (EF) Core for Identity management.

## Getting Started

### Prerequisites

- [.NET Core SDK](https://dotnet.microsoft.com/download) (version 8.0 or later)
- [Visual Studio](https://visualstudio.microsoft.com/) (optional, but recommended)

### Setup

1. Clone the repository:

    ```bash
    git clone https://github.com/mhmmdkhoulani/JWTRefreshToken.git
    cd JWTRefreshToken
    ```

2. Set up the SQL Server database:
   
    - Open `appsettings.json` and modify the connection string to your SQL Server instance.

    ```json
    "ConnectionStrings": {
        "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=YourDatabase;Integrated Security=True;"
    },
    ```

    - Run EF Core migrations to apply database changes:

    ```bash
    dotnet ef database update
    ```

3. Configure JWT settings:

    - Open `appsettings.json` and update the JWT settings:

    ```json
    "AuthSetting": {
        "Key": "YourSecretKey",
        "Issuer": "YourIssuer",
        "Audience": "YourAudience",
        "DurationInMinutes": 30
    }
    ```

4. Build and run the project:

    ```bash
    dotnet build
    dotnet run
    ```


## Endpoints

The following endpoints are available:

- **POST /api/auth/register**: Register a new user.
- **POST /api/auth/login**: Log in and receive JWT and refresh tokens.
- **GET /api/auth/refreshtoken**: Refresh the JWT using a valid refresh token.
- **POST /api/auth/revoketoken**: Log out and invalidate the refresh token.
- **POST /api/auth/AddToRole**: Add user to role.

## Usage

1. Register a new user using the `/api/auth/register` endpoint.
2. Log in using the `/api/auth/login` endpoint to obtain JWT and refresh tokens.
3. Use the obtained JWT for authorized requests to secure endpoints.
4. Refresh the JWT using the `/api/auth/refreshtoken` endpoint when it expires.
5. Log out using the `/api/auth/revoketoken` endpoint to invalidate the refresh token.
6. Add user to role using the `/api/auth/addtorole` endpoint to add the user to role.

## Contributing

Feel free to contribute to this project. Open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).
