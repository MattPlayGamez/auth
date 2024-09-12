# Authenticator Library

A Node.js-based authentication library that provides user registration, login, password management, and Two-Factor Authentication (2FA) support using bcrypt for hashing, JWT for tokens, and speakeasy/QRCode for 2FA implementation.

## Table of Contents

- [Authenticator Library](#authenticator-library)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Features](#features)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Register a user](#register-a-user)
    - [Login](#login)
    - [Password Reset](#password-reset)
    - [Two-Factor Authentication (2FA)](#two-factor-authentication-2fa)
    - [Token verification](#token-verification)
    - [User Management](#user-management)
  - [Configuration](#configuration)
  - [Dependencies](#dependencies)

## Introduction

The `Authenticator` class handles the core authentication and authorization process for applications. It supports user registration, login with password verification, optional Two-Factor Authentication (2FA), and token-based session management.

## Features

- **Password Hashing**: Secure password storage using bcrypt.
- **JWT Authentication**: Token-based session handling using JSON Web Tokens.
- **Two-Factor Authentication (2FA)**: Optional support for time-based OTPs using speakeasy and QR codes.
- **Login Attempts Lock**: Automatically lock a user after a configurable number of failed login attempts.
- **User Management**: Retrieve, lock, unlock, and manage users.
- **Remove User**: Remove a user from the system.

## Installation

```bash
npm install bcrypt jsonwebtoken uuid speakeasy qrcode
```

## Usage
First, import the `@mattplaygamez/auth` class and configure it:

### Register a user
To register a new user, create a user object and pass it to the register method.
```javascript
const Authenticator = require('@mattplaygamez/auth');
````

```javascript
const userObject = {
  email: 'user@example.com',
  password: 'yourpassword',
  wants2FA: true
};

const auth = new Authenticator('YourAppLabel', 10, 'your_jwt_secret', { expiresIn: '1h' }, 5, []);
const newUser = await auth.register(userObject);
console.log(newUser);
```
If the user opts for 2FA (wants2FA: true), a QR code will be generated.

### Login
To log in, provide the email, password, and 2FA code (if enabled). A JWT token is returned on successful login.
```javascript
const email = 'user@example.com';
const password = 'yourpassword';
const twoFactorCode = '123456';  // Only needed if 2FA is enabled, otherwise type null

const user = await auth.login(email, password, twoFactorCode);
// OR
const user = await auth.login(email, password, null); // No 2FA
console.log(user.jwt_token);  // JWT token is returned here

```
### Password Reset
You can reset the user's password by calling the resetPassword method:
```javascript
await auth.resetPassword(userId, 'newPassword');
```
### Two-Factor Authentication (2FA)
- **Add 2FA**: You can add 2FA for a user after registration or while registering:

```javascript
await auth.add2FA(userId);
```
OR
```javascript
await auth.register({
  email: 'user@example.com',
  password: 'yourpassword',
  wants2FA: true // If the user doesn't need/want 2FA, then don't include this property or set it to false
});
```
-  **Remove 2FA**: To remove 2FA for a user:
```javascript
await auth.remove2FA(userId);   
```
### Token verification
You can verify tokens using the `verifyToken` method:
```javascript
const decoded = await auth.verifyToken(token);
console.log(decoded);
```
### User Management
  - **Get User by ID**: Retrieve user information based on their ID.
  ```javascript
  const userInfo = auth.getInfoFromUser(userId);
  ```
  - **Lock/Unlock User**: Lock or unlock a user after failed login attempts:
  ```javascript
  await auth.lockUser(userId);
  await auth.unlockUser(userId);
  ```
  - **Remove A User**: Remove a user based on their ID
  ```javascript
  await auth.removeUser(userId)
  ```
## Configuration

The `Authenticator` constructor requires several parameters to customize its behavior:
```javascript
new Authenticator(QR_LABEL, salt, JWT_SECRET_KEY, JWT_OPTIONS, maxLoginAttempts, userObject);
```
- QR_LABEL: Label used for 2FA QR codes.
- salt: Salt rounds for bcrypt hashing.
- JWT_SECRET_KEY: Secret key for JWT tokens.
- JWT_OPTIONS: Options for JWT token configuration (e.g., expiration time).
- maxLoginAttempts: Maximum number of login attempts before the account is locked.
- userObject: An array or object to store users.

## Dependencies

- bcrypt: Used to securely hash and compare passwords.
- jsonwebtoken: Handles token creation and verification.
- uuid: Generates unique IDs for users.
- speakeasy: Provides 2FA support using time-based one-time passwords (TOTP).
- qrcode: Generates QR codes for 2FA setup.
