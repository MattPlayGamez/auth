# Seamless-auth

A versatile and secure authentication module for Node.js applications.



## Features

- Support for multiple storage methods: MongoDB, encrypted file, or in-memory
- User registration and login
- Password hashing with bcrypt
- JWT token verification
- Two-factor authentication (2FA) with QR codes
- Login attempt limiting and user locking
- Password reset and 2FA management

## Installation

Install the module via npm:

```bash
npm install seamless-auth
```

## Usage

Import the desired version of the authenticator:

```javascript
// For MongoDB support
const Authenticator = require('seamless-auth/mongodb');
// For encrypted file storage
const Authenticator = require('seamless-auth/file');
// For in-memory storage
const Authenticator = require('seamless-auth/memory');


```
If you use MongoDB, you NEED to make a schema with these values as a minimum.
You can add as many fields as you need. (e.g., phone number, address)

```javascript
const DB_SCHEMA = {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    loginAttempts: { type: Number, default: 0 },
    locked: { type: Boolean, default: false },
    emailCode: { type: String, default: "", required: false, unique: true },
    wants2FA: { type: Boolean, default: false },
    secret2FA: String
}
```

Initialize the authenticator with the required parameters:

```javascript

const auth = new Authenticator(
QR_LABEL,
SALT,
JWT_SECRET_KEY,
JWT_OPTIONS,
MAX_LOGIN_ATTEMPTS,
USER_OBJECT // Only for memory authentication
DB_CONNECTION_STRING, //for MONGODB or DB_FILE_PATH for file storage
DB_SCHEMA, // for MONGODB schema  
DB_PASSWORD // only for file storage
);
```


## API

### `register(userObject)`
Registers a new user.

### `login(email, password, twoFactorCode || null)`
Logs in a user.

### `getInfoFromUser(userId)`
Retrieves user information.

### `verifyToken(token)`
Verifies a JWT token.

### `verify2FA(userId, twoFactorCode)`
Verifies a 2FA code.
Useful for reverifying user identity when accessing sensitive functions

### `resetPassword(userId, newPassword)`
Resets a user's password.

### `changeLoginAttempts(userId, attempts)`
Changes the number of login attempts for a user.

### `lockUser(userId)`
Locks a user account.

### `unlockUser(userId)`
Unlocks a user account.

### `remove2FA(userId)`
Removes 2FA for a user.

### `add2FA(userId)`
Adds 2FA for a user.

### `registerEmailSignin(email)`
Generates a OTP so the user can use passwordless login, using their email

### `verifyEmailSignin(emailCode)`
Verifies the OTP from the user and responds with a valid jwt_token

### `revokeUserTokens(userId)`
Revokes all existing JWT token for that user

### `removeUser(userId)`
Removes a user.

### `isAuthenticated(req)`
Checks if a user is authenticated using the token from the cookies from the request and provides the user as req.user

## Example
Encrypted File
```javascript
const Authenticator = require('seamless-auth/file.js');
const auth = new Authenticator(
    'MyApp',
    12,
    'my_secret_key',
    { expiresIn: '1h' },
    5,
    './users.db',
    'db_password'
);

```
Memory storage (ephemeral)

```javascript
import Authenticator from 'seamless-auth/memory'
let USERS = [] // If you want to have existing users, add here
const auth = new Authenticator(
    'MyApp',
    12,
    'your_jwt_secret',
    { expiresIn: '1h' },
    5,
    USERS
);
```

```javascript
const Authenticator = require('seamless-auth/file');
const auth = new Authenticator(
'MyApp',
12,
'your_jwt_secret',
{ expiresIn: '1h' },
5,
'./users.db',
'db_password'
);
// Register a new user
const registerResult = await auth.register({
    email: 'user@example.com',
    password: 'secure_password',
    wants2FA: true
});
console.log(registerResult);

const loginResult = await auth.login('user@example.com', 'secure_password', '123456');
console.log(loginResult);
// OR   
const emailCode = await auth.registerEmailSignin('user@example.com'); // Sent code to users email or phone number

token = await auth.verifyEmailSignin(emailCode) // emailCode is that code that the user sends back, can be because a link he clicked or just when he filled the code in
console.log(token.jwt_token); // It responds with a JSON WEB TOKEN

await auth.revokeUserTokens(userId)
```
Check authentication
```javascript
await Auth.isAuthenticated(req)
if (isAuth) // do something
```

middleware to check authentication
```javascript
const checkAuth = async (req, res,next) => {
    let isAuth = await Auth.isAuthenticated(req)
    if (!isAuth) return res.redirect('/login')
    next()
}
```

```javascript
import Authenticator from "../mongodb.js";

let DB_SCHEMA = {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    loginAttempts: { type: Number, default: 0 },
    locked: { type: Boolean, default: false },
    wants2FA: { type: Boolean, default: false },
    secret2FA: String
}


let connectionString = "CONNECTIONSTRING" // The connection string for MongoDB
const auth = new Authenticator('MyApp', 12, 'your_jwt_secret', { expiresIn: '1 ' }, 5, connectionString, DB_SCHEMA);

```

## License

Mozilla Public License, v. 2.0

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For questions or support, please open an issue on the GitHub repository.