// Local file is not written to disk
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')
const fs = require('fs');
const Crypto = require('node:crypto')


const algorithm = 'aes-256-ctr';

class Authenticator {

    /**
     * Constructor for the Authenticator class
     * @param {string} QR_LABEL - label for the QR code
     * @param {number} rounds - number of rounds for bcrypt
     * @param {string} JWT_SECRET_KEY - secret key for signing JWTs
     * @param {object} JWT_OPTIONS - options for JWTs such as expiresIn
     * @param {number} maxLoginAttempts - maximum number of login attempts
     * @param {string} DB_FILE_PATH - path to the file where the users are stored
     * @param {string} DB_PASSWORD - password to decrypt the file
     */
    constructor(QR_LABEL, rounds, JWT_SECRET_KEY, JWT_OPTIONS, maxLoginAttempts, USER_ARRAY) {
        this.QR_LABEL = QR_LABEL;
        this.rounds = rounds;
        this.JWT_SECRET_KEY = JWT_SECRET_KEY;
        this.JWT_OPTIONS = JWT_OPTIONS;
        this.maxLoginAttempts = maxLoginAttempts - 2;
        this.users = USER_ARRAY;
        this.OTP_ENCODING = 'base32'
        this.lockedText = "User is locked"
        this.OTP_WINDOW = 1 // How many OTP codes can be used before and after the current one (usefull for slower people, recommended 1)
        this.INVALID_2FA_CODE_TEXT = "Invalid 2FA code"
        this.REMOVED_USER_TEXT = "User has been removed"
        this.USER_ALREADY_EXISTS_TEXT = "User already exists"
        this.ALLOW_DB_DUMP = false // Allowing DB Dumping is disabled by default can be enabled by setting ALLOW_DB_DUMP to true after initializing your class


    }



    /**
     * Registers a new user
     * @param {object} userObject - object with required keys: email, password, wants2FA, you can add custom keys too
     * @returns {object} - registered user object, or "User already exists" if user already exists
     * @throws {Error} - any other error
     */
    async register(userObject) {
        if (!userObject.loginAttempts) userObject.loginAttempts = 0
        if (!userObject.locked) userObject.locked = false
        if (!userObject._id) userObject._id = uuid.v4()
        userObject.locked = false
        userObject.emailCode = null
        let returnedUser = userObject
        try {
            const hash = await bcrypt.hash(userObject.password, this.rounds);
            if (userObject.wants2FA) {
                const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
                const otpauth_url = speakeasy.otpauthURL({
                    secret: secret.base32,
                    label: this.QR_LABEL,
                    encoding: this.OTP_ENCODING
                });
                const qrCode = await QRCode.toDataURL(otpauth_url);
                userObject.secret2FA = secret.base32;
                returnedUser.qrCode = qrCode;
            }
            returnedUser.password = hash;
            userObject.password = hash;
            userObject.jwt_version = 1


            if (this.users.find(u => u.email === userObject.email)) return this.USER_ALREADY_EXISTS_TEXT
            this.users.push(userObject);
            return returnedUser;
        } catch (err) {
            console.log(err)
        }

    }

    /**
     * Logs in a user
     * @param {string} email - email address of user
     * @param {string} password - password of user
     * @param {number} twoFactorCode - 2FA code of user or put null if user didn't provide a 2FA
     * @returns {object} - user object with jwt_token, or null if login was unsuccessful, or "User is locked" if user is locked
     * @throws {Error} - any other error
     */
    async login(email, password, twoFactorCode) {
        const account = this.users.find(u => u.email === email);
        if (!email) return null;
        if (!password) return null;

        try {
            if (account.locked) return this.lockedText
            const result = await bcrypt.compare(password, account.password);

            if (!result) {

                (account.loginAttempts >= this.maxLoginAttempts) ? this.lockUser(account.id) : await this.changeLoginAttempts(account._id, account.loginAttempts + 1)

                return null
            };
            if (account) {
                if (account.wants2FA) {
                    if (twoFactorCode === undefined) {
                        return null;
                    }


                    const verified = speakeasy.totp.verify({
                        secret: account.secret2FA,
                        encoding: this.OTP_ENCODING,
                        token: twoFactorCode,
                        window: this.OTP_WINDOW
                    });
                    if (!verified) return this.INVALID_2FA_CODE_TEXT;

                }
                const jwt_token = jwt.sign({ _id: account._id, version: account.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
                this.changeLoginAttempts(account._id, 0)

                return { ...account, jwt_token };
            }
        } catch (err) {
            throw err;
        }
    }
    /**
     * Generates a random string (emailCode) and updates the user object with it
     * @param {string} email - email address of user
     * @returns {string} - emailCode
     * @throws {Error} - any other error
     */
    async registerEmailSignin(email) {
        let emailCode = Crypto.randomUUID()
        try {
            const user = this.users.find(u => u.email === email);
            if (!user) return null;
            if (user.locked) return this.lockedText;
            const userIndex = this.users.findIndex(u => u.email === email);
            if (userIndex !== -1) {
                this.users[userIndex].emailCode = emailCode;
            }
            this.users.push()
            return emailCode;

        } catch (error) {
            console.error(error)
        }
    }
    /**
     * Verifies a emailCode and returns a valid JWT token for the user
     * @param {string} emailCode - the emailCode to verify
     * @returns {object} - an object with the user info and a valid JWT token
     * @throws {Error} - any error that occurs during the process
     */
    async verifyEmailSignin(emailCode) {
        if (emailCode === null) return null
        const user = await this.users.find(user => user.emailCode == emailCode);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.emailCode === emailCode);
        if (userIndex !== -1) {
            this.users[userIndex].emailCode = null;
        }
        const jwt_token = jwt.sign({ _id: user._id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
        this.users.push()
        return { ...user, jwt_token };
    }
    /**
     * Retrieves user information based on the user ID
     * @param {string} userId - the user ID to retrieve information
     * @returns {object} - an object with the user information
     * @throws {Error} - any error that occurs during the process
     */
    getInfoFromUser(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        return user
    }
    /**
     * Retrieves user information based on the user email
     * @param {string} email - the email to retrieve information
     * @returns {object} - an object with the user information
     * @throws {Error} - any error that occurs during the process
     */

    getInfoFromEmail(email) {
        const user = this.users.find(u => u.email === email);
        if (!user) return null;
        return user
    }
    /**
     * Verifies a JWT token and returns the user information if the token is valid
     * @param {string} token - the JWT token to verify
     * @returns {object} - the user information if the token is valid, otherwise false
     * @throws {Error} - any error that occurs during the process
     */
    async verifyToken(token) {
        if (jwt.verify(token, this.JWT_SECRET_KEY, this.JWT_OPTIONS)) {
            let jwt_token = jwt.decode(token);
            let user = await this.getInfoFromUser(jwt_token._id)
            return (user.jwt_version === jwt_token.version) ? this.getInfoFromUser(jwt_token._id) : false;
        }
    }
    /**
     * Verifies a 2FA code for a user
     * @param {string} userId - the user ID to verify the 2FA code for
     * @param {string} twofactorcode - the 2FA code to verify
     * @returns {boolean} - true if the code is valid, false otherwise
     */
    async verify2FA(userId, twofactorcode) {
        let user = this.users.find(user => user._id === userId)
        if (!user) return null
        const verified = speakeasy.totp.verify({
            secret: user.secret2FA,
            encoding: this.OTP_ENCODING,
            token: twofactorcode,
            window: this.OTP_WINDOW
        });
        return verified;

    }
    /**
     * Resets the password of a user
     * @param {string} userId - the user ID to reset the password for
     * @param {string} newPassword - the new password to set
     * @returns {object} - the user object after the password has been reset
     * @throws {Error} - any error that occurs during the process
     */
    async resetPassword(userId, newPassword) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        user.password = await bcrypt.hash(newPassword, this.rounds);
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].password = user.password;
            this.users[userIndex].jwt_version += 1
        }
        this.users.push()

        return user;
    }
    /**
     * Changes the number of login attempts for a user
     * @param {string} userId - the user ID to change the login attempts for
     * @param {number} attempts - the new number of login attempts
     * @returns {object} - the user object after the login attempts have been changed
     * @throws {Error} - any error that occurs during the process
     */
    async changeLoginAttempts(userId, attempts) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].loginAttempts = attempts;
        }
        this.users.push()

        return user;
    }
    /**
     * Locks a user from logging in
     * @param {string} userId - the user ID to lock
     * @returns {object} - the user object after the user has been locked
     * @throws {Error} - any error that occurs during the process
     */
    async lockUser(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].locked = true;
        }
        this.users.push()

        return user;
    }
    /**
     * Unlocks a user from logging in
     * @param {string} userId - the user ID to unlock
     * @returns {object} - the user object after the user has been unlocked
     * @throws {Error} - any error that occurs during the process
     */
    async unlockUser(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].locked = false;
        }
        this.users.push()
        return user;
    }
    /**
     * Revokes all user tokens for a user
     * @param {string} userId - the user ID to revoke all tokens for
     * @returns {undefined}
     * @throws {Error} - any error that occurs during the process
     */
    async revokeUserTokens(userId) {
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].jwt_version += 1;
        }
        this.users.push()


    }
    /**
     * Removes 2FA for a user
     * @param {string} userId - the user ID to remove 2FA for
     * @returns {object} - the user object after 2FA has been removed
     * @throws {Error} - any error that occurs during the process
     */
    async remove2FA(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].wants2FA = false;
            user.wants2FA = false
            this.users[userIndex].secret2FA = "";
            user.secret2FA = false
            this.users[userIndex].qrCode = "";
            user.qrCode = false
        }
        this.users.push()

        return user;
    }
    /**
     * Adds 2FA for a user
     * @param {string} userId - the user ID to add 2FA for
     * @returns {object} - the user object after 2FA has been added
     * @throws {Error} - any error that occurs during the process
     */
    async add2FA(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
        const otpauth_url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: this.QR_LABEL,
            encoding: this.OTP_ENCODING
        });
        const qrCode = await QRCode.toDataURL(otpauth_url);
        if (userIndex !== -1) {
            this.users[userIndex].wants2FA = true;
            user.wants2FA = true
            this.users[userIndex].secret2FA = secret.base32;
            user.secret2FA = secret.base32
            user.qrCode = qrCode
        }
        this.users.push()

        return user;
    }
    /**
     * Removes a user from the database
     * @param {string} userId - the user ID to remove
     * @returns {string} - "User has been removed" if successful, otherwise an error message
     * @throws {Error} - any error that occurs during the process
     */
    async removeUser(userId) {
        try {
            const user = this.users.find(u => u._id === userId);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users.splice(userIndex, 1);
            }
            this.users.push()
            return this.REMOVED_USER_TEXT

        } catch (error) {
            return `User with ID ${userId} couldn't be removed`

        }


    }
    /**
     * Retrieves all users from the database
     * @returns {object[]} - an array of user objects
     * @throws {Error} - any error that occurs during the process
     */
    async dumpDB() {
        if (this.ALLOW_DB_DUMP === false) return "DB dumping is disabled"
        return this.users
    }

    /**
     * Verifies if a request is authenticated
     * @param {object} req - the Express request object
     * @returns {boolean} - true if the request is authenticated, otherwise false
     * @throws {Error} - any error that occurs during the process
     */
    async isAuthenticated(req) {
        try {
            const rawCookies = req.headers.cookie || '';
            const cookies = {};
            rawCookies.split(';').forEach(cookie => {
                const [key, value] = cookie.trim().split('=');
                cookies[key] = decodeURIComponent(value);
            });

            const token = cookies.token;
            console.log(token)
            let user = await this.verifyToken(token)
            console.log(user)
            if (!token) {
                return false;
            }
            if (!user) {
                return false;
            }
            req.user = user;
            return true
        } catch (err) {
            console.log(err)
        }
    }

}

module.exports = Authenticator
