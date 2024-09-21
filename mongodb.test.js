require("dotenv/config")
const mongoose = require('mongoose');
const Authenticator = require('./mongodb.js')
const jwt = require('jsonwebtoken');


// Mock the user schema and Mongoose model
const userSchema = new mongoose.Schema({
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
  email: "test@example.com",
  password: "password123",
  wants2FA: false,
};


// MongoDB connection string (mocked for tests)
const MONGODB_CONNECTION_STRING = process.env.MONGODB_CONNECTION_STRING;



describe('Authenticator Class Tests', () => {
  let authenticator;
  let userID = 0

  beforeAll(async () => {
    authenticator = new Authenticator(
      'TestApp', 10, 'secretKey123', { expiresIn: '1h' }, 3, MONGODB_CONNECTION_STRING, userSchema
    );
  });



  test('User Registration without 2FA', async () => {
    const result = await authenticator.register(mockUser);
    expect(result.user.email).toBe(mockUser.email);
    expect(result.user.jwt_version).toBe(1);
    expect(result.user.wants2FA).toBe(false);
  });

  test('User Login', async () => {
    const loginResult = await authenticator.login(mockUser.email, mockUser.password);
    userID = loginResult._id
    expect(loginResult.jwt_token).toBeDefined();
    expect(jwt.verify(loginResult.jwt_token, 'secretKey123')).toBeTruthy();
  });

  test('Get Info From User', async () => {
    const info = await authenticator.getInfoFromUser(userID)
    
  })

  test('Verify JWT Token', async () => {
    const loginResult = await authenticator.login(mockUser.email, mockUser.password);
    const tokenVerification = await authenticator.verifyToken(loginResult.jwt_token);
    expect(tokenVerification).toBe(true);
  });

  test('Login with incorrect password', async () => {
    const result = await authenticator.login(mockUser.email, 'wrongpassword');
    expect(result).toBe(null);
  });
  test('Unlock user after max login attempt', async () => {
    const resp = await authenticator.unlockUser(userID)
    expect(resp.locked).toBe(false);
  })

  test('Lock user after max login attempts', async () => {
    await authenticator.login(mockUser.email, 'wrongpassword');
    await authenticator.login(mockUser.email, 'wrongpassword');
    const result = await authenticator.login(mockUser.email, 'wrongpassword');
    if (result === 'User is locked') {
      expect(result).toBe('User is locked');
    } else {
      expect(result).toBeNull();
    }
  });
  test('Delete user', async () => {
    let response = await authenticator.removeUser(userID)
    expect(response.email).toBe()
  });



  afterAll(async () => {
    await authenticator.User.collection.drop();
  });

  // Add more tests to cover other functionalities like 2FA, email sign-in, etc.
});

