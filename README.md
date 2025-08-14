# 2FA Authentication App Backend - Secure RESTful API

![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=flat&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat&logo=mongodb&logoColor=white)
![Mongoose](https://img.shields.io/badge/Mongoose-880000?style=flat&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=flat&logo=jsonwebtokens&logoColor=white)
![Jest](https://img.shields.io/badge/Jest-C21325?style=flat&logo=jest&logoColor=white)
![Cloudinary](https://img.shields.io/badge/Cloudinary-3448C5?style=flat&logo=cloudinary&logoColor=white)

A secure and scalable RESTful API for a **2-Factor Authentication (2FA)** application, built with **Node.js**, **Express**, and **MongoDB**. This backend provides robust user authentication with **JWT cookie-based auth**, **OTP-based email verification**, and **2FA**. It includes advanced features like role-based access control, password reset via email, avatar uploads with **Cloudinary**, and an admin dashboard for user management. Automated tasks like user ban removal are handled by **node-cron** and **node-schedule**, while **Jest** and **Supertest** ensure comprehensive test coverage.

## ✨ Features

- **Role-Based Authentication**: Secure access control with admin and user roles.
- **JWT Cookie-Based Auth**: Stateless authentication using HTTP-only cookies for enhanced security.
- **2FA with OTP**: Two-factor authentication via email-based OTP, with account lockout for 10 minutes after 5 failed attempts.
- **Email Verification**: OTP-based email verification, with account deletion after 5 failed attempts.
- **Password Reset**: Token-based password reset with email delivery via **Nodemailer**.
- **Avatar Upload**: Profile picture uploads using **Multer** and **Cloudinary**.
- **Admin Dashboard**: View weekly registered users, recent users, and banned users; manage bans and user deletion.
- **Rate Limiting**: Protects API endpoints from abuse using **express-rate-limit**.
- **Security Headers**: Enhanced security with **Helmet** middleware.
- **Scheduled Tasks**: Real-time user ban removal with **node-cron** and **node-schedule**.
- **Testing**: Comprehensive unit and integration tests with **Jest** and **Supertest**, all tests passing successfully.
- **Logging**: Request logging with **Morgan** for debugging and monitoring.

## 🛠️ Technologies Used

- **Node.js & Express**: Scalable server-side framework for RESTful APIs.
- **MongoDB**: NoSQL database for flexible user and authentication data storage.
- **Mongoose**: ORM for streamlined MongoDB operations.
- **JWT**: Cookie-based authentication with JSON Web Tokens.
- **Nodemailer**: Email delivery for OTPs and password reset tokens.
- **Cloudinary & Multer**: Cloud-based storage for user avatar uploads.
- **express-rate-limit**: Rate limiting to prevent API abuse.
- **Helmet**: Security headers for enhanced protection.
- **node-cron & node-schedule**: Scheduled tasks for automated ban removal.
- **Jest & Supertest**: Unit and integration testing for robust code quality.
- **pnpm**: Fast and disk-efficient package manager.
- **Nodemon**: Development server with hot reloading.
- **Morgan**: HTTP request logging for debugging.

## 🚀 Getting Started

### Prerequisites
- Node.js (v16.x or higher)
- MongoDB (local or MongoDB Atlas)
- pnpm (preferred) or npm
- Git
- Cloudinary account (for avatar uploads)
- Email service credentials (for Nodemailer)

### Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/mrtmrngz/auth-app-backend-2fa.git
   cd auth-app-nodejs-mongodb
   ```

2. **Install Dependencies**:
   ```bash
   pnpm install
   # or
   npm install
   # or
   yarn
   ```

3. **Set Up Environment Variables**:
   - Create a `.env` file in the root directory with the following:
     ```env
     MONGO_URI=your_mongodb_connection_string
     MONGO_URI_TEST=your_mongodbtest_connection_string
     JWT_ACCESS_SECRET=your_jwt_access_token_secret_key
     JWT_REFRESH_SECRET=your_jwt_refresh_token_secret_key
     JWT_MAIL_SECRET=your_jwt_mail_token_secret_key
     APP_MAIL=your_email_service_email
     APP_PASSWORD=your_email_service_password
     CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
     CLOUDINARY_API_KEY=your_cloudinary_api_key
     CLOUDINARY_API_SECRET=your_cloudinary_api_secret
     CLIENT_URL=your_clint_url
     PORT=5000
     ```

4. **Run the Application**:
   - Development mode (with hot reloading):
     ```bash
     pnpm dev
     # or
     npm run dev
     # or
     yarn dev
     ```
   - Production mode:
     ```bash
     pnpm start
     # or
     npm start
     # or
     yarn start
     ```
   - The API will be available at `http://localhost:5000`.

5. **Run Tests**:
   - Execute unit and integration tests:
     ```bash
     pnpm test
     # or
     npm test
     # or
     yarn test
     ```

## 🖥️ Usage
- **Register/Login**: Use `POST /api/auth/register` or `POST /api/auth/login` to authenticate and receive a JWT cookie.
- **Email Verification**: Verify email with OTP sent via `POST /api/auth/verify-otp`; account deletes after 5 failed attempts.
- **2FA**: Enable 2FA with `POST /api/users/enable-two-factor` and verify with OTP; account locks for 10 minutes after 5 failed attempts.
- **Password Reset**: Request a reset token via `POST /api/auth/reset-password-mail` and update password with `POST /api/auth/reset-password-apply`.
- **Avatar Upload**: Upload profile pictures via `PATCH /api/users/change-user-infos` using Multer and Cloudinary.
- **Admin Dashboard**: Access `/api/admin` endpoints (admin-only) to view user stats, manage bans, and delete users.
- **Scheduled Tasks**: Automated ban removal runs via `node-cron` and `node-schedule`.

## 📂 Project Structure
```
auth-app-nodejs-mongodb/
├── controllers/            # Request handlers for API endpoints
│   ├── admin.controller.js
│   ├── auth.controller.js
│   └── user.controller.js
├── middleware/             # Authentication, rate limiting, and security middleware
│   ├── protected-routes.js
│   └── user-auth-middleware.js
├── libs/                   # Utility functions and configurations
│   └── upload.js
├── routes/                 # Express routes for API endpoints
│   ├── auth.route.js
│   ├── user.route.js
│   ├── admin.route.js
│   └── index.route.js
├── jobs/                   # Scheduled tasks for ban removal (node-cron, node-schedule)
├── server.js               # Main entry point for the Express server
├── .env                    # Environment variables
├── .gitignore              # Files ignored by Git
├── package.json            # Project dependencies and scripts
└── README.md               # Project documentation
```

## 🛠️ API Endpoints
| Method | Endpoint                        | Description                          |
|--------|---------------------------------|--------------------------------------|
| POST   | `/api/auth/register`            | Register a new user                  |
| POST   | `/api/auth/verify-otp`          | Verify email with OTP                |
| POST   | `/api/auth/resend-otp`          | Resend email verification OTP        |
| POST   | `/api/auth/login`               | Log in and receive JWT cookie        |
| POST   | `/api/auth/reset-password-mail` | Request password reset token         |
| POST   | `/api/auth/reset-password-apply`| Reset password with token            |
| GET    | `/api/auth/get-token`           | Retrieve authentication token        |
| POST   | `/api/auth/logout`              | Log out and invalidate JWT           |
| GET    | `/api/users/user-info`          | Get user information (user-only)     |
| PATCH  | `/api/users/enable-two-factor`  | Enable 2FA for the user              |
| PATCH  | `/api/users/change-mail-or-username` | Update email or username (user-only) |
| PATCH  | `/api/users/change-user-infos`  | Update user info and avatar (user-only) |
| GET    | `/api/admin/has-access`         | Check admin access (admin-only)      |
| GET    | `/api/admin/dashboard`          | View admin dashboard stats (admin-only) |
| PATCH  | `/api/admin/ban-user`           | Ban a user (admin-only)              |
| PATCH  | `/api/admin/unban-user`         | Unban a user (admin-only)            |
| PATCH  | `/api/admin/update-user/:id`    | Update user details (admin-only)     |
| DELETE | `/api/admin/delete-user/:id`    | Delete a user (admin-only)           |

## 🤝 Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature`.
3. Make changes and commit: `git commit -m "Your message"`.
4. Push to your branch: `git push origin feature/your-feature`.
5. Open a pull request with a clear description.

Please use pnpm for dependency management and ensure tests pass (`pnpm test`) before submitting.

## 📜 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 📬 Contact
For questions or feedback, reach out to [mrtmrngz](https://github.com/mrtmrngz) or email [mert00marangoz@gmail.com](mailto:mert00marangoz@gmail.com).

## 🌟 Acknowledgements
- Inspired by modern authentication systems with 2FA and admin controls.
- Thanks to the open-source community for tools like Mongoose, Nodemailer, Cloudinary, and Jest.