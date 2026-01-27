# TaskBook - A Project Management System

TaskBook is a powerful and intuitive project management system designed to help you and your team stay organized and productive. It provides a comprehensive set of features to manage projects, tasks, and team members effectively. This project was built to showcase a robust backend implementation with a focus on security, scalability, and maintainability.

## Features

### Authentication

*   **User Registration:** Create a new user account with an avatar.
*   **Email Verification:** Verify your email address to activate your account.
*   **Login:** Securely log in to your account.
*   **Logout:** Log out of your account.
*   **Password Management:** Change your password and reset it if you forget it.
*   **Access Token Refresh:** Keep your session active with automatic access token refreshing.
*   **User Profile:** View and manage your user profile.

### Project Management

*   **Create Projects:** Start new projects with a name and description.
*   **Project Dashboard:** View all your projects in one place.
*   **Project Details:** See a detailed view of a specific project.
*   **Update Projects:** Edit project details as needed.
*   **Delete Projects:** Remove projects that are no longer active.
*   **Project Status:** Update the status of your projects (e.g., "In Progress," "Completed").
*   **Team Management:**
    *   Add or remove team members from a project.
    *   Assign roles and permissions to team members.
    *   View all members of a project.

### Task Management

*   **Create Tasks:** Add new tasks to your projects with a title and description.
*   **Task List:** View all tasks for a specific project.
*   **Task Details:** See a detailed view of a specific task.
*   **Update Tasks:**
    *   Change the title and description of a task.
    *   Update the status of a task (e.g., "To Do," "In Progress," "Done").
    *   Assign or reassign tasks to team members.

## Features in Detail

### 1. Robust Authentication System

*   **Complexity:** The authentication system is a critical part of the application and requires a high level of security. It involves handling user credentials, managing sessions, and protecting against common vulnerabilities like Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF).
*   **Implementation:**
    *   **Password Hashing:** Passwords are never stored in plain text. We use the `bcrypt` library to hash and salt passwords before storing them in the database.
    *   **JSON Web Tokens (JWT):** We use JWTs for session management. When a user logs in, a signed access token and a refresh token are generated and sent to the client. The access token is used to authenticate subsequent requests, while the refresh token is used to obtain a new access token when the old one expires.
    *   **Email Verification:** To ensure that users provide a valid email address, we send a verification email with a unique token. This is implemented using the `nodemailer` library.
    *   **Secure Password Reset:** The forgot password functionality is implemented by generating a unique, short-lived token that is sent to the user's email. This token can be used to reset the password.

### 2. Advanced Project and Task Management

*   **Complexity:** The core of the application is the ability to manage projects and tasks. This involves creating a relational data model to represent the relationships between projects, tasks, users, and roles. The system also needs to handle permissions to ensure that users can only access and modify the data they are authorized to.
*   **Implementation:**
    *   **MongoDB and Mongoose:** We use MongoDB as our database and Mongoose as our Object Data Modeling (ODM) library. Mongoose allows us to define schemas for our data, which helps to ensure data consistency and provides a convenient way to interact with the database.
    *   **RESTful API:** The backend exposes a RESTful API that allows the frontend to perform CRUD (Create, Read, Update, Delete) operations on projects and tasks.
    *   **Data Validation:** We use the `express-validator` library to validate all incoming data to ensure that it meets the required format and constraints.

### 3. Role-Based Access Control (RBAC)

*   **Complexity:** Implementing a flexible and secure RBAC system is a complex task. It requires a clear definition of roles and permissions, and a mechanism to enforce these permissions at the API level.
*   **Implementation:**
    *   **Permissions and Roles:** We have defined a set of permissions (e.g., `create:project`, `delete:task`) and roles (e.g., `admin`, `member`). Roles are assigned to users on a per-project basis.
    *   **Middleware:** We have created a custom middleware that checks the user's permissions for each request. This middleware is applied to the relevant API routes to ensure that only authorized users can access them.

### 4. File Uploads with Cloudinary

*   **Complexity:** Handling file uploads can be challenging, especially when dealing with large files and the need for a scalable storage solution.
*   **Implementation:**
    *   **Multer:** We use the `multer` middleware to handle file uploads from the client.
    *   **Cloudinary:** Instead of storing files on our own server, we use Cloudinary, a cloud-based image and video management service. This allows us to offload the storage and delivery of files, which improves the performance and scalability of our application.

## API Endpoints

The TaskBook API provides the following endpoints to interact with the application:

### Authentication

| Method | Endpoint                                  | Description                     |
| ------ | ----------------------------------------- | ------------------------------- |
| POST   | /api/v1/auth/register                     | Register a new user             |
| GET    | /api/v1/auth/verify-email/:verificationToken | Verify a user's email           |
| POST   | /api/v1/auth/resend-verification-email    | Resend verification email       |
| POST   | /api/v1/auth/login                        | Log in a user                   |
| GET    | /api/v1/auth/logout                       | Log out a user                  |
| POST   | /api/v1/auth/change-current-password      | Change the current password     |
| POST   | /api/v1/auth/forgot-password-request      | Request a password reset        |
| POST   | /api/v1/auth/reset-forgotten-password/:forgotPasswordToken | Reset a forgotten password      |
| POST   | /api/v1/auth/refresh-token                | Refresh an access token         |
| GET    | /api/v1/auth/get-user                     | Get the current user's details  |

### Projects

| Method | Endpoint                                  | Description                       |
| ------ | ----------------------------------------- | --------------------------------- |
| POST   | /api/v1/projects/create                   | Create a new project              |
| GET    | /api/v1/projects                          | Get all projects                  |
| GET    | /api/v1/projects/:projectId               | Get a project by ID               |
| PATCH  | /api/v1/projects/:projectId/update        | Update a project                  |
| DELETE | /api/v1/projects/:projectId/delete        | Delete a project                  |
| PATCH  | /api/v1/projects/:projectId/update-status | Update a project's status         |
| GET    | /api/v1/projects/:projectId/project-members | Get all members of a project      |
| POST   | /api/v1/projects/:projectId/add-member    | Add a member to a project         |
| PATCH  | /api/v1/projects/:projectId/:userId/update-role | Update a member's role          |
| DELETE | /api/v1/projects/:projectId/:userId/remove | Remove a member from a project    |

### Tasks

| Method | Endpoint                                  | Description                  |
| ------ | ----------------------------------------- | ---------------------------- |
| POST   | /api/v1/tasks/:projectId/createTask       | Create a new task            |
| GET    | /api/v1/tasks/:projectId/allTasks         | Get all tasks for a project  |
| GET    | /api/v1/tasks/:projectId/:taskId          | Get a task by ID             |
| PATCH  | /api/v1/tasks/:projectId/:taskId/updateTaskTitle | Update a task's title        |
| PATCH  | /api/v1/tasks/:projectId/:taskId/updateTaskDesc | Update a task's description  |
| PATCH  | /api/v1/tasks/:projectId/:taskId/updateTaskStatus | Update a task's status       |
| PATCH  | /api/v1/tasks/:projectId/:taskId/updateTaskAssignees | Update a task's assignees    |

## Getting Started

### Prerequisites

*   Node.js and npm
*   MongoDB
*   Git

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/TaskBook---A-Project-Management-System.git
    cd TaskBook---A-Project-Management-System/Taskbook-app/taskbook-backend
    ```

2.  **Install dependencies:**

    ```bash
    npm install
    ```

3.  **Set up environment variables:**

    Create a `.env` file in the `taskbook-backend` directory and add the following environment variables:

    ```
    PORT=3000
    MONGODB_URI=your-mongodb-connection-string
    CORS_ORIGIN=*
    ACCESS_TOKEN_SECRET=your-access-token-secret
    ACCESS_TOKEN_EXPIRY=1d
    REFRESH_TOKEN_SECRET=your-refresh-token-secret
    REFRESH_TOKEN_EXPIRY=10d
    CLOUDINARY_CLOUD_NAME=your-cloudinary-cloud-name
    CLOUDINARY_API_KEY=your-cloudinary-api-key
    CLOUDINARY_API_SECRET=your-cloudinary-api-secret
    MAIL_HOST=your-mail-host
    MAIL_PORT=your-mail-port
    MAIL_USER=your-mail-user
    MAIL_PASS=your-mail-pass
    ```

### Running the Application

```bash
npm start
```

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.