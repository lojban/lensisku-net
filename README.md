# Lensisku .NET API

This document provides instructions on how to set up and run the Lensisku .NET API locally.

## Prerequisites

*   .NET SDK (version compatible with the project, e.g., .NET 7.0 or newer)
*   PostgreSQL server (already running and accessible)

## Environment Setup

1.  **Navigate to the .NET project directory:**
    ```bash
    cd lensisku-net
    ```

2.  **Create a `.env` file:**
    This file will store your local configuration, including database connection details and JWT secrets. Create a file named `.env` in the `lensisku-net` directory.

    You can copy the structure from the root `.env.example` file and adapt it, or create a new one with the following essential variables:

    ```env
    # PostgreSQL Database Connection
    # Option 1: Using a single DATABASE_URL
    DATABASE_URL="Host=localhost;Port=5432;Database=your_db_name;Username=your_db_user;Password=your_db_password;"

    # Option 2: Using individual parameters (if DATABASE_URL is not set, the application might look for these or expect them in appsettings.json, but DATABASE_URL is preferred as per Program.cs)
    # DB_HOST=localhost
    # DB_PORT=5432
    # DB_NAME=your_db_name
    # DB_USER=your_db_user
    # DB_PASSWORD=your_db_password

    # JWT Settings
    JWT_SECRET="your_super_secret_jwt_key_here_make_it_long_and_random"
    JWT_ISSUER="your_application_issuer_uri_e.g_https_localhost_7001" # Replace 7001 with your actual HTTPS port
    JWT_AUDIENCE="your_application_audience_uri_e.g_https_localhost_7001" # Replace 7001 with your actual HTTPS port

    # Other optional variables from the root .env.example can be included if needed by specific services,
    # but the above are crucial for basic operation and auth.
    ```

    **Important Notes for `.env`:**
    *   Replace placeholder values (like `your_db_name`, `your_db_user`, `your_super_secret_jwt_key_here_make_it_long_and_random`, etc.) with your actual configuration.
    *
     The `DATABASE_URL` format is a standard PostgreSQL connection string. Ensure it matches your PostgreSQL setup.
    *   `JWT_SECRET` should be a strong, random string.
    *   `JWT_ISSUER` and `JWT_AUDIENCE` should ideally be the URI where your application is running.

## Running the Application

1.  **Ensure you are in the project directory:**
    ```bash
    cd lensisku-net
    ```

2.  **Restore dependencies (if first time or dependencies changed):**
    `dotnet restore` downloads and installs all NuGet package dependencies defined in the .csproj file.
    ```bash
    dotnet restore
    ```

3.  **Run the application:**
    `dotnet run` builds and starts the application.
    ```bash
    dotnet run
    ```
    The application will start, and by default, it usually listens on `http://localhost:5106` (or similar ports, check the console output for the exact URLs).

## Accessing Swagger UI

Once the application is running, you can access the Swagger UI in your web browser to explore and test the API endpoints.

*   Navigate to: `http://localhost:<your_https_port>/swagger`
    (e.g., `http://localhost:5106/swagger` if your app runs HTTPS on port 5106. Check the application's console output for the correct HTTPS port.)

    However, development often defaults to HTTPS.

This interface allows you to see all available API endpoints, their request/response schemas, and execute requests directly.

## Project Structure and Concepts (Compared to Nest.js)

This section provides an overview of the Lensisku .NET API's structure and key concepts, with comparisons to common patterns found in Nest.js for developers familiar with that framework.

### Directory Tree Structure

The project follows a feature-based organization, primarily within the `Auth/` directory for authentication and user-related functionalities.

*   **`lensisku-net/`** (Root project directory)
    *   **`Auth/`**: Contains all authentication and user management related code.
        *   **`Controllers/`**: Holds API controllers (e.g., `AuthController.cs`).
            *   *Nest.js equivalent*: `*.controller.ts` files.
        *   **`DTOs/`**: (Data Transfer Objects) Defines classes for request and response payloads (e.g., `LoginRequestDto.cs`, `TokenResponseDto.cs`).
            *   *Nest.js equivalent*: `dto/*.dto.ts` files, often used with validation pipes.
        *   **`Models/`**: Contains Entity Framework Core (EF Core) entity classes that map to database tables (e.g., `User.cs`, `Role.cs`).
            *   *Nest.js equivalent*: Entity definitions for ORMs like TypeORM or Prisma (`*.entity.ts`).
        *   **`Services/`**: Contains business logic services (e.g., `AuthService.cs`, `UserService.cs`, `TokenService.cs`). Interfaces for these services (e.g., `IAuthService.cs`) are also typically in this folder.
            *   *Nest.js equivalent*: `*.service.ts` files, injectable services.
    *   **`Data/`**: Contains database-related configurations.
        *   `AppDbContext.cs`: The Entity Framework Core DbContext class, responsible for database interaction.
            *   *Nest.js equivalent*: Database module configuration, TypeORM `DataSource` or Prisma client setup.
    *   **`Properties/`**: Contains project configuration files like `launchSettings.json` (for local development server settings).
    *   `Program.cs`: The main entry point of the application. Configures services, middleware, and the HTTP request pipeline.
        *   *Nest.js equivalent*: `main.ts` and `app.module.ts` (for global module setup, middleware, DI).
    *   `JwtSettings.cs`: A POCO class for JWT configuration.
    *   `.env`, `.env.example`: Environment variable files for configuration.
    *   `appsettings.json`, `appsettings.Development.json`: JSON configuration files.
    *   `lensisku-net.csproj`: The MSBuild project file, defining dependencies and project settings.
        *   *Nest.js equivalent*: `package.json`.

### Controllers

Controllers are responsible for handling incoming HTTP requests, processing them (often by delegating to services), and returning HTTP responses. In ASP.NET Core, controllers are classes that typically inherit from `ControllerBase`.

*   **Example**: `AuthController.cs`
*   **Attributes**:
    *   `[ApiController]`: Enables API-specific behaviors like automatic model validation.
    *   `[Route("api/[controller]")]`: Defines the base route for the controller.
    *   `[HttpGet]`, `[HttpPost]`, etc.: Define routes for specific action methods.
    *   `[Authorize]`: Restricts access to authenticated users (or based on policies/roles).
*   **Dependency Injection**: Services are injected into controllers via constructors.
*   *Nest.js equivalent*: Controllers decorated with `@Controller()`, methods with `@Get()`, `@Post()`, etc. Dependencies are injected via constructors.

### DTOs (Data Transfer Objects)

DTOs are simple classes used to define the shape of data for API requests and responses. They help in validating incoming data and structuring outgoing data. Data annotations (e.g., `[Required]`, `[StringLength]`) are often used for validation.

*   **Example**: `LoginRequestDto.cs`, `ProfileResponseDto.cs`
*   **Validation**: ASP.NET Core automatically validates DTOs bound from the request body if `[ApiController]` is used. `ModelState.IsValid` can be checked in controller actions.
*   *Nest.js equivalent*: DTO classes, often used with `class-validator` and `class-transformer` for validation and transformation, typically applied via `ValidationPipe`.

### Database Connection (Entity Framework Core)

The application uses Entity Framework Core (EF Core) as its Object-Relational Mapper (ORM) to interact with a PostgreSQL database.

*   **`AppDbContext.cs`**: Inherits from `DbContext`. It defines `DbSet<TEntity>` properties for each entity (table) and configures entity relationships and mappings in the `OnModelCreating` method.
*   **Configuration**: The database connection string is typically loaded from `appsettings.json` or environment variables (via `.env`) and configured in `Program.cs` when registering
`AppDbContext`.
    ```csharp
    // In Program.cs
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseNpgsql(connectionString));
    ```
*   *Nest.js equivalent*: Using ORMs like TypeORM or Prisma. Configuration involves setting up a `DataSource` (TypeORM) or Prisma Client, often within a dedicated database module. Entities are defined as classes with decorators.

### Service Logic Construction

Services encapsulate the business logic of the application. They are injected into controllers or other services.

*   **Interfaces and Implementations**: It's a common practice to define an interface (e.g., `IAuthService`) and its concrete implementation (e.g., `AuthService`). This promotes loose coupling and
testability.
*   **Dependency Injection**: Services are registered with the DI container in `Program.cs` (e.g., `builder.Services.AddScoped<IAuthService, AuthService>();`) and then injected via constructors where needed.
*   **Async Operations**: Services often perform asynchronous operations (e.g., database calls, external API requests) and return `Task` or `Task<T>`.
*   *Nest.js equivalent*: Services are classes decorated with `@Injectable()`. They are registered as providers in modules and injected into controllers or other services via constructors.

### Other Important Features

*   **Dependency Injection (DI)**: ASP.NET Core has a built-in DI container. Services are registered in `Program.cs` and resolved automatically by the framework.
    *   *Nest.js equivalent*: Nest.js has its own powerful DI system, central to its architecture.
*   **Authentication & Authorization**:
    *   **Authentication**: JWT Bearer authentication is configured in `Program.cs`. `TokenService` is responsible for generating JWTs.
    *   **Authorization**: Implemented using `[Authorize]` attributes on controllers/actions. Policies (e.g., `ManageRolesPolicy`) can be defined for more granular control, checking for specific
claims (like permissions or roles).
    *   *Nest.js equivalent*: Authentication is often handled via Passport.js strategies. Authorization uses Guards, which can implement role-based or claims-based access control.
*   **Middleware**: The HTTP request pipeline is configured in `Program.cs` using `app.Use...()` methods (e.g., `app.UseAuthentication()`, `app.UseAuthorization()`, `app.UseHttpsRedirection()`).
    *   *Nest.js equivalent*: Middleware functions (`*.middleware.ts`) can be applied globally, to specific modules, or to specific routes.
*   **Configuration Management**: Settings are loaded from `appsettings.json`, environment-specific files (e.g., `appsettings.Development.json`), and environment variables (via `.env` loaded by
`DotNetEnv`). The `IConfiguration` service provides access to these settings.
    *   *Nest.js equivalent*: `ConfigModule` is commonly used to manage environment variables and configuration files.
*   **Error Handling**: `[ApiController]` provides default problem details for errors. Custom error handling can be implemented using exception middleware.
    *   *Nest.js equivalent*: Exception Filters (`*.filter.ts`) are used to catch and handle exceptions, allowing for customized error responses.
*   **Logging**: ASP.NET Core provides a built-in logging framework. `ILogger<T>` is injected into services and controllers to log messages.
    *   *Nest.js equivalent*: Built-in `Logger` service, or integration with libraries like Winston or Pino.

This .NET project mirrors many of the architectural principles found in Nest.js, such as modularity (though less explicit than Nest.js modules), dependency injection, service-oriented
architecture, and clear separation of concerns between controllers, services, and data models/DTOs. The use of attributes in .NET for routing, validation, and authorization is analogous to
decorators in Nest.js.