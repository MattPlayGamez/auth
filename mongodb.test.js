require("dotenv/config")
const mongoose = require('mongoose');
const Authenticator = require('./mongodb.js')
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');


// Mock the user schema and Mongoose model
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  jwt_version: Number,
  wants2FA: Boolean,
  secret2FA: String,
  loginAttempts: Number,
  locked: Boolean,
  emailCode: String,
});

const mockUser = {
  username: "test",
  email: "test@example.com",
  password: "password123",
  wants2FA: false,
};

const mockUser2FA = {
  username: "test2",
  email: "test2@example.com",
  password: "password123",
  wants2FA: true,
};


// MongoDB connection string (mocked for tests)
const MONGODB_CONNECTION_STRING = process.env.MONGODB_CONNECTION_STRING;


describe('Authenticator Class Tests', () => {
  let authenticator;
  let userID = 0
  let userID2FA = 0
  let SECRET2FA = ""
  const JWT_SECRET = "secretKey123"
  let userToken1 = ""
  let emailCode = ""


  beforeAll(async () => {
    authenticator = new Authenticator(MONGODB_CONNECTION_STRING, userSchema)
    authenticator.rounds = 10
    authenticator.JWT_SECRET_KEY = JWT_SECRET
    authenticator.ALLOW_DB_DUMP = true

  });



  test('User Registration without 2FA', async () => {
    const result = await authenticator.register(mockUser);
    expect(result.email).toBe(mockUser.email);
    expect(result.jwt_version).toBe(1);
    expect(result.wants2FA).toBe(false);
  });
  test('User Registration with 2FA', async () => {
    const result = await authenticator.register(mockUser2FA);
    expect(result.email).toBe(mockUser2FA.email);
    expect(result.jwt_version).toBe(1);
    expect(result.wants2FA).toBe(true);
    SECRET2FA = result.secret2FA
    expect(result.secret2FA).not.toBeUndefined();
    expect(result.qrCode).not.toBeUndefined();
  });

  test('User Login', async () => {
    const loginResult = await authenticator.login(mockUser.username, mockUser.password);
    userID = loginResult._id
    expect(loginResult.jwt_token).toBeDefined();
    expect(jwt.verify(loginResult.jwt_token, JWT_SECRET)).toBeTruthy();
    userToken1 = loginResult.jwt_token
  });

  test('User Login with 2FA', async () => {
    const twoFactorCode = speakeasy.totp({
      secret: SECRET2FA,
      encoding: 'base32',
    })
    const loginResult = await authenticator.login(mockUser2FA.username, mockUser2FA.password, twoFactorCode);
    userID2FA = loginResult._id
    expect(loginResult.jwt_token).toBeDefined();
    expect(jwt.verify(loginResult.jwt_token, JWT_SECRET)).toBeTruthy();
  });

  test('User Login with invalid 2FA ', async () => {
    const loginResult = await authenticator.login(mockUser2FA.username, mockUser2FA.password, 100000);
    expect(loginResult.jwt_token).not.toBeDefined();
  });
  test('User Login with no 2FA (for a 2FA user) ', async () => {
    const loginResult = await authenticator.login(mockUser2FA.username, mockUser2FA.password, 100000);
    expect(loginResult.jwt_token).not.toBeDefined();
  });

  test('Login with incorrect password', async () => {
    const result = await authenticator.login(mockUser.username, 'wrongpassword');
    expect(result).toBe("Invalid credentials");
  });

  test('Get Info From User', async () => {
    const info = await authenticator.getInfoFromUser(userID)
    expect(info.email).toBe(mockUser.email);
  })

  test('Get Info From Custom Field (e.g. email)', async () => {
    const info = await authenticator.getInfoFromCustom("email", mockUser.email)
    expect(info.email).toBe(mockUser.email);
  })

  test('Verify JWT Token', async () => {
    const loginResult = await authenticator.login(mockUser.username, mockUser.password);
    const tokenVerification = await authenticator.verifyToken(loginResult.jwt_token);
    expect(tokenVerification).toBeDefined()
  });

  test('Verify 2FA code', async () => {
    const twoFactorCode = speakeasy.totp({
      secret: SECRET2FA,
      encoding: 'base32',
    })
    const result = await authenticator.verify2FA(userID2FA, twoFactorCode)
    expect(result).toBe(true);
  });

  test('Reset Password', async () => {
    let newPassword = "newpassword123"
    const result = await authenticator.resetPassword(userID, newPassword)
    mockUser.password = newPassword
    expect(result.email).toBe(mockUser.email);
  })

  test('Change Login Attempts', async () => {
    let newAttempts = 10
    const result = await authenticator.changeLoginAttempts(userID, newAttempts)
    expect(result.loginAttempts).toBe(newAttempts);
    await authenticator.changeLoginAttempts(userID, 0)
  })

  test('Lock user', async () => {
    let result = await authenticator.lockUser(userID)
    expect(result.locked).toBe(true);
  })

  test('Unlock user after max login attempt', async () => {
    const resp = await authenticator.unlockUser(userID)
    expect(resp.locked).toBe(false);
  })

  test('Lock user after max login attempts', async () => {
    await authenticator.login(mockUser.username, 'wrongpassword');
    await authenticator.login(mockUser.username, 'wrongpassword');
    await authenticator.login(mockUser.username, 'wrongpassword');
    const result = await authenticator.login(mockUser.username, 'wrongpassword');
    expect(result).toBe(authenticator.LOCKED_TEXT);
    await authenticator.unlockUser(userID)
  });


  test('Remove 2FA', async () => {
    let response = await authenticator.remove2FA(userID2FA)
    expect(response.wants2FA).toBe(false)
    expect(response.secret2FA).toBe('')
  });
  test('Add 2FA', async () => {
    let response = await authenticator.add2FA(userID2FA)
    SECRET2FA = response.secret2FA
    expect(response.wants2FA).toBe(true)
    expect(response.secret2FA).not.toBeUndefined()
  })

  test('Register Email Signin (send code)', async () => {
    await new Promise(resolve => setTimeout(resolve, 500));
    let response = await authenticator.registerEmailSignin(mockUser.email)
    emailCode = response
    expect(emailCode).not.toBeUndefined()
  })
  test('Verify Email Signin (verify code)', async () => {
    await new Promise(resolve => setTimeout(resolve, 500));
    let jwt_token = await authenticator.verifyEmailSignin(emailCode)
    console.log("response")
    console.log(jwt_token)
    expect(jwt_token).not.toBeUndefined()

  })
  test('Verify Email Signin (verify code) With fake code', async () => {
    await new Promise(resolve => setTimeout(resolve, 100));
    let jwt_token = await authenticator.verifyEmailSignin("emailCode")
    expect(jwt_token).toBe(null)

  })

  test('Revoke All User Tokens', async () => {
    await authenticator.revokeUserTokens(userID)
    const user1 = await authenticator.verifyToken(userToken1)
    expect(user1).toBe(false)
  })

  test('Delete user', async () => {
    let response = await authenticator.removeUser(userID2FA)
    expect(response.email).toBe()
  });

  test('Check if user is authenticated', async () => {
    await authenticator.register({
      username: "test3",
      email: "test3@test.test",
      password: "test3",
      wants2FA: false,
    })
    let currentUser = await authenticator.login("test3", "test3")
    console.log(currentUser)

    let response = await authenticator.isAuthenticated(currentUser.jwt_token)
    expect(response.email).toBe("test3@test.test")
  })

  test('Check if user is authenticated with invalid token', async () => {
    await authenticator.register({
      username: "test4",
      email: "test4@test.test",
      password: "test4",
      wants2FA: false,
    })
    let currentUser = await authenticator.login("test4", "test4")
    console.log(currentUser)

    let response = await authenticator.isAuthenticated("invalid_token")
    expect(response).toBe(false)
  })


  afterAll(async () => {
    await authenticator.dumpDB()
    await authenticator.User.collection.drop();
  });


});
