const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')
const mongoose = require('mongoose')
const Crypto = require('node:crypto')

// Creëer het gebruikersmodel

class Authenticator {
    /**
     * Constructor for the Authenticator class
     * @param {string} QR_LABEL - label for the QR code
     * @param {number} salt - salt for hashing passwords
     * @param {string} JWT_SECRET_KEY - secret key for signing JWTs
     * @param {object} JWT_OPTIONS - options for JWTs such as expiresIn
     * @param {number} maxLoginAttempts - maximum number of login attempts
     * @param {string} MONGODB_CONNECTION_STRING - connection string for MongoDB
     * @param {mongoose.Schema} userSchema - schema for the User model
     */
    constructor(QR_LABEL, salt, JWT_SECRET_KEY, JWT_OPTIONS, maxLoginAttempts, MONGODB_CONNECTION_STRING, userSchema) {
        this.QR_LABEL = QR_LABEL;
        this.salt = salt;
        this.JWT_SECRET_KEY = JWT_SECRET_KEY;
        this.JWT_OPTIONS = JWT_OPTIONS;
        this.maxLoginAttempts = maxLoginAttempts;
        mongoose.connect(MONGODB_CONNECTION_STRING);
        this.User = mongoose.model('User', userSchema)
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
     * @returns {object} - registered user object, or "Gebruiker bestaat al" if user already exists
     * @throws {Error} - any other error
     */
    async register(userObject) {
        try {
            const hash = await bcrypt.hash(userObject.password, this.salt);
            let newUser = new this.User({
                ...userObject,
                password: hash,
                jwt_version: 1
            });

            if (userObject.wants2FA) {
                const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
                const otpauth_url = speakeasy.otpauthURL({
                    secret: secret.base32,
                    label: this.QR_LABEL,
                    encoding: this.OTP_ENCODING
                });
                newUser.secret2FA = secret.base32;
                await newUser.save();
                newUser.qrCode = await QRCode.toDataURL(otpauth_url);
                return newUser
            }
            await newUser.save();


            if (!userObject.wants2FA) {
                return newUser;
            }

        } catch (err) {
            if (err.code === 11000) {
                return this.USER_ALREADY_EXISTS_TEXT;
            }
            console.log(err);
            throw err;
        }
    }

    /**
     * Logs in a user
     * @param {string} email - email address of the user
     * @param {string} password - password of the user
     * @param {number} twoFactorCode - 2FA code if user has 2FA enabled
     * @returns {object} - logged in user object with JWT or qrCode if user has 2FA enabled
     * @throws {Error} - any other error
     */
    async login(email, password, twoFactorCode) {
        const user = await this.User.findOne({ email });
        if (!user) return null;

        try {
            if (user.locked) return this.lockedText
            const result = await bcrypt.compare(password, user.password);
            if (!result) {

                if (user.loginAttempts >= this.maxLoginAttempts) {

                    this.lockUser(user._id);
                } else {
                    let newAttempts = user.loginAttempts + 1
                    await this.changeLoginAttempts(user._id, newAttempts);
                }
                return null;
            };
            if (user) {
                if (user.wants2FA) {
                    if (twoFactorCode === undefined) {
                        // Genereer QR-code voor de eerste respons
                        const otpauth_url = speakeasy.otpauthURL({
                            secret: user.secret2FA,
                            label: this.QR_LABEL,
                            encoding: this.OTP_ENCODING
                        });
                        const qrCode = await QRCode.toDataURL(otpauth_url);
                        return { qrCode };
                    }

                    const verified = speakeasy.totp.verify({
                        secret: user.secret2FA,
                        encoding: this.OTP_ENCODING,
                        token: twoFactorCode,
                        window: this.OTP_WINDOW
                    });
                    if (!verified) return this.INVALID_2FA_CODE_TEXT;

                }
                const jwt_token = jwt.sign({ _id: user._id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);

                this.changeLoginAttempts(user._id, 0)

                return { ...user.toObject(), jwt_token };
            }
        } catch (err) {
            throw err;
        }
    }
    /**
     * Generates a one time password and stores it in the user record. This is used
     * for passwordless login, where the user will receive this code and can login
     * with it.
     * @param {string} email - the email of the user
     * @returns {object} - object with a single key: emailCode, the code that the user
     *                    needs to enter to login
     * @throws {Error} - any error that occurs during the process
     */
    async registerEmailSignin(email) {
        let emailCode = Crypto.randomUUID()
        try {
            if (await this.User.findOne({ email: email }).locked) return this.lockedText
            await this.User.findOneAndUpdate({ email: email }, { emailCode: emailCode })
            return { emailCode }

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
        if (!emailCode || typeof emailCode !== 'string') return null;

        const user = await this.User.findOne({ emailCode });
        if (!user) return null;

        await this.User.findOneAndUpdate({ emailCode }, { emailCode: "" });

        const jwt_token = jwt.sign(
            { _id: user._id, version: user.jwt_version },
            this.JWT_SECRET_KEY,
            this.JWT_OPTIONS
        );

        return { ...user.toObject(), jwt_token };
    }
    /**
     * Retrieves user information based on the user ID
     * @param {string} userId - the user ID to retrieve information
     * @returns {object} - an object with the user information
     * @throws {Error} - any error that occurs during the process
     */
    async getInfoFromUser(userId) {
        return await this.User.findOne({ _id: userId });
    }
    /**
     * Retrieves user information based on the user's email address
     * @param {string} email - the email address to retrieve information
     * @returns {object} - an object with the user information
     * @throws {Error} - any error that occurs during the process
     */
    async getInfoFromEmail(email) {
        return await this.User.findOne({ email: email });
    }

    /**
     * Verifies a JWT token and returns the user information if the token is valid
     * @param {string} token - the JWT token to verify
     * @returns {object} - the user information if the token is valid, otherwise false
     * @throws {Error} - any error that occurs during the process
     */
    async verifyToken(token) {

        try {

            if (jwt.verify(token, this.JWT_SECRET_KEY, this.JWT_OPTIONS)) {
                let jwt_token = jwt.decode(token);
                let user = await this.getInfoFromUser(jwt_token._id)
                return (user.jwt_version === jwt_token.version) ? this.getInfoFromUser(jwt_token._id) : false;
            }
        } catch (error) {
            console.log(error)

        }
    }
    /**
     * Verifies a 2FA code for a user
     * @param {string} userId - the user ID to verify the 2FA code for
     * @param {string} twofactorcode - the 2FA code to verify
     * @returns {boolean} - true if the code is valid, false otherwise
     */
    async verify2FA(userId, twofactorcode) {
        let user = await this.User.findOne({ _id: userId })
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
        this.revokeUserTokens(userId)
        const hash = await bcrypt.hash(newPassword, this.salt);
        return await this.User.findOneAndUpdate({ _id: userId }, { password: hash }, { new: true })

    }
    /**
     * Changes the number of login attempts for a user
     * @param {string} userId - the user ID to change the login attempts for
     * @param {number} attempts - the new number of login attempts
     * @returns {object} - the user object after the login attempts have been changed
     * @throws {Error} - any error that occurs during the process
     */
    async changeLoginAttempts(userId, attempts) {
        return await this.User.findOneAndUpdate({ _id: userId }, { loginAttempts: attempts }, { new: true });

    }
    /**
     * Locks a user from logging in
     * @param {string} userId - the user ID to lock
     * @returns {object} - the user object after the user has been locked
     * @throws {Error} - any error that occurs during the process
     */
    async lockUser(userId) {
        return await this.User.findOneAndUpdate({ _id: userId }, { locked: true }, { new: true });
    }
    /**
     * Unlocks a user from logging in
     * @param {string} userId - the user ID to unlock
     * @returns {object} - the user object after the user has been unlocked
     * @throws {Error} - any error that occurs during the process
     */
    async unlockUser(userId) {
        return await this.User.findOneAndUpdate({ _id: userId }, { locked: false }, { new: true });
    }

    /**
     * Revokes all user tokens for a user
     * @param {string} userId - the user ID to revoke all tokens for
     * @returns {object} - the user object after the tokens have been revoked
     * @throws {Error} - any error that occurs during the process
     */
    async revokeUserTokens(userId) {
        let newVersion = (await this.User.findOne({ _id: userId })).jwt_version + 1
        return await this.User.findOneAndUpdate({ _id: userId }, { jwt_version: newVersion }, { new: false });
    }
    /**
     * Removes 2FA for a user
     * @param {string} userId - the user ID to remove 2FA for
     * @returns {object} - the user object after 2FA has been removed
     * @throws {Error} - any error that occurs during the process
     */
    async remove2FA(userId) {
        return await this.User.findOneAndUpdate(
            { _id: userId },
            { wants2FA: false, secret2FA: "", qrCode: "" },
            { new: true }
        );
    }
    /**
     * Adds 2FA for a user
     * @param {string} userId - the user ID to add 2FA for
     * @returns {object} - the user object after 2FA has been added
     * @throws {Error} - any error that occurs during the process
     */
    async add2FA(userId) {
        const user = await this.User.findOne({ _id: userId });
        if (!user) return null;

        const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
        const otpauth_url = speakeasy.otpauthURL({

            secret: secret.base32,
            label: this.QR_LABEL,
            encoding: this.OTP_ENCODING
        });
        const qrCode = await QRCode.toDataURL(otpauth_url);

        return await this.User.findOneAndUpdate(
            { _id: userId },
            { wants2FA: true, secret2FA: secret.base32, qrCode },
            { new: true }
        );
    }
    /**
     * Removes a user from the database
     * @param {string} userId - the user ID to remove
     * @returns {string} - "User has been removed" if successful, otherwise an error message
     * @throws {Error} - any error that occurs during the process
     */
    async removeUser(userId) {
        try {
            await this.User.findOneAndDelete({ _id: userId });
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
        return await this.User.find()
    }

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
