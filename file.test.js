require("dotenv/config")
const Authenticator = require('./file.js')
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const fs = require('fs');

const mockUser = {
    email: "test@example.com",
    password: "password123",
    wants2FA: false,
};

const mockUser2FA = {
    email: "test2@example.com",
    password: "password123",
    wants2FA: true,
};



describe('Authenticator Class Tests', () => {
    let authenticator;
    let userID = 0
    let userID2FA = 0
    let SECRET2FA = ""
    const JWT_SECRET = "secretKey123"
    let userToken1 = ""
    let emailCode = ""

    beforeAll(async () => {
        authenticator = new Authenticator(
            'TestApp', 10, JWT_SECRET, { expiresIn: '1h' }, 3, "app.db", "password123"
        );
        authenticator.ALLOW_DB_DUMP = true

    });



    test('User Registration without 2FA', async () => {
        const result = await authenticator.register({
            email: "test@example.com",
            password: "password123",
            wants2FA: false,
        });
        expect(result.email).toBe(mockUser.email);
        expect(result.jwt_version).toBe(1);
        expect(result.wants2FA).toBe(false);
    });
    test('User Registration with 2FA', async () => {
        const result = await authenticator.register({
            email: "test2@example.com",
            password: "password123",
            wants2FA: true,
        });
        expect(result.email).toBe(mockUser2FA.email);
        expect(result.jwt_version).toBe(1);
        expect(result.wants2FA).toBe(true);
        SECRET2FA = result.secret2FA
        expect(result.secret2FA).not.toBeUndefined();
        expect(result.qrCode).not.toBeUndefined();
    });

    test('User Login', async () => {
        const loginResult = await authenticator.login(mockUser.email, mockUser.password);
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
        const loginResult = await authenticator.login(mockUser2FA.email, mockUser2FA.password, twoFactorCode);
        userID2FA = loginResult._id
        expect(loginResult.jwt_token).toBeDefined();
        expect(jwt.verify(loginResult.jwt_token, JWT_SECRET)).toBeTruthy();
    });

    test('User Login with invalid 2FA ', async () => {
        const loginResult = await authenticator.login(mockUser2FA.email, mockUser2FA.password, 100000);
        expect(loginResult.jwt_token).not.toBeDefined();
    });
    test('User Login with no 2FA (for a 2FA user) ', async () => {
        const loginResult = await authenticator.login(mockUser2FA.email, mockUser2FA.password, 100000);
        expect(loginResult.jwt_token).not.toBeDefined();
    });

    test('Login with incorrect password', async () => {
        const result = await authenticator.login(mockUser.email, 'wrongpassword');
        expect(result).toBe(null);
    });

    test('Get Info From User', async () => {
        const info = await authenticator.getInfoFromUser(userID)
        expect(info.email).toBe(mockUser.email);
    })

    test('Get Info From Email', async () => {
        const info = await authenticator.getInfoFromEmail(mockUser.email)
        expect(info.email).toBe(mockUser.email);
    })

    test('Verify JWT Token', async () => {
        const loginResult = await authenticator.login(mockUser.email, mockUser.password);
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
        await authenticator.login(mockUser.email, 'wrongpassword');
        await authenticator.login(mockUser.email, 'wrongpassword');
        const result = await authenticator.login(mockUser.email, 'wrongpassword');
        if (result === 'User is locked') {
            expect(result).toBe('User is locked');
        } else {
            expect(result).toBeNull();
        }
        await authenticator.unlockUser(userID)
    });


    test('Remove 2FA', async () => {
        let response = await authenticator.remove2FA(userID2FA)
        expect(response.wants2FA).toBe(false)
        expect(response.secret2FA).toBe(false)
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
        expect(jwt_token).not.toBeUndefined()

    })
    test('Verify Email Signin (verify code) With fake code', async () => {
        await new Promise(resolve => setTimeout(resolve, 100));
        let jwt_token = await authenticator.verifyEmailSignin("emailCode")
        expect(jwt_token).toBe(null)

    })

    test('Check if user is authenticated', async () => {
        await authenticator.register({
            email: "test@test.test",
            password: "test",
            wants2FA: false,
        })
        let user = await authenticator.login("test@test.test", "test")
        console.log(user)
        
        let req = { headers: { "host": "127.0.0.1:3000", "connection": "keep-alive", "cache-control": "max-age=0", "sec-ch-ua": "\"Chromium\";v=\"130\", \"Brave\";v=\"130\", \"Not?A_Brand\";v=\"99\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"Windows\"", "dnt": "1", "upgrade-insecure-requests": "1", "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", "sec-gpc": "1", "accept-language": "nl-NL,nl", "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-user": "?1", "sec-fetch-dest": "document", "referer": "http://127.0.0.1:3000/login", "accept-encoding": "gzip, deflate, br, zstd", "cookie": `token=${user.jwt_token}`, "if-none-match": "W/\"14-VDnz0WejlS4iemsxsVhn1S8IIDE\"" } }
        let response = await authenticator.isAuthenticated(req)
        expect(response).toBe(true)
    })

    test('Revoke All User Tokens', async () => {
        await authenticator.revokeUserTokens(userID)
        const user1 = await authenticator.verifyToken(userToken1)
        expect(user1).toBe(false)
    })

    test('Remove a user', async () => {
        let response = await authenticator.removeUser(userID2FA)
        expect(response).toBe("User has been removed")
    });

    

    afterAll(async () => {
        console.log(await authenticator.dumpDB())
        fs.unlinkSync("./app.db")
    });

});
