// Local file is written to disk
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')
const fs = require('fs');
const Crypto = require('node:crypto')


const algorithm = 'aes-256-ctr';

// Helper functions
function encrypt(text, password) {
    const rounds = Crypto.randomBytes(16);
    const key = Crypto.scryptSync(password, rounds, 32);
    const iv = Crypto.randomBytes(16);
    const cipher = Crypto.createCipheriv(algorithm, key, iv);
    let crypted = cipher.update(text, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return rounds.toString('hex') + iv.toString('hex') + crypted;
}

function decrypt(encryptedText, password) {
    const rounds = Buffer.from(encryptedText.slice(0, 32), 'hex');
    const iv = Buffer.from(encryptedText.slice(32, 64), 'hex');
    const key = Crypto.scryptSync(password, rounds, 32);
    const decipher = Crypto.createDecipheriv(algorithm, key, iv);
    let dec = decipher.update(encryptedText.slice(64), 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}

function saveUsersToFile(users, filePath, password) {
    const data = JSON.stringify(users);
    const encryptedData = encrypt(data, password);
    fs.writeFileSync(filePath, encryptedData, 'utf8');
}

function loadUsersFromFile(filePath, password) {
    if (!fs.existsSync(filePath)) return [];
    const encryptedData = fs.readFileSync(filePath, 'utf8');
    const data = decrypt(encryptedData, password);
    return JSON.parse(data);
}

// Load users from file on startup

class Authenticator {


    constructor() {
        this.QR_LABEL = "Authenticator";
        this.rounds = 12;
        this.JWT_SECRET_KEY = "changeme";
        this.JWT_OPTIONS = { expiresIn: "1h" };
        this.maxLoginAttempts = 3
        this.DB_FILE_PATH = "./users.db"
        this.DB_PASSWORD = "changeme"
        this.users = loadUsersFromFile(this.DB_FILE_PATH, this.DB_PASSWORD);
        this.OTP_ENCODING = 'base32'
        this.LOCKED_TEXT = "User is locked"
        this.OTP_WINDOW = 1 // How many OTP codes can be used before and after the current one (usefull for slower people, recommended 1)
        this.INVALID_2FA_CODE_TEXT = "Invalid 2FA code"
        this.REMOVED_USER_TEXT = "User has been removed"
        this.USERNAME_ALREADY_EXISTS_TEXT = "This username already exists"
        this.EMAIL_ALREADY_EXISTS_TEXT = "This email already exists"
        this.USERNAME_IS_REQUIRED = "Username is required"
        this.PASSWORD_IS_REQUIRED = "Password is required"
        this.INVALID_CREDENTIALS_TEXT = "Invalid credentials"
        this.ALLOW_DB_DUMP = false // Allowing DB Dumping is disabled by default can be enabled by setting ALLOW_DB_DUMP to true after initializing your class

        // Override methods to update file when users array changes
        const originalPush = this.users.push;

        this.users.push = (...args) => {
            const result = originalPush.apply(this.users, args);
            saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);
            return result;
        };

    }




    /**
     * Registers a new user.
     *
     * Initializes user object with default values if not provided, including login attempts,
     * locked status, and unique ID. ashes the password and optionally generates a 2FA secret
     * and QR code if 2FA is requested. Checks for existing user by email and returns an
     * appropriate message if user already exists. Updates users list and returns the
     * registered user object.
     *
     * @param {object} userObject - The user details containing required keys:
     *                              username, email, password, wants2FA. Custom keys can be added like.
     *                              If email is null or undefined, they can't use login by email.
     * @returns {object|string} - The registered user object or a string "User already exists".
     * @throws {Error} - Logs any error encountered during registration process.
     */
    async register(userObject) {
        try {
            if (!userObject.loginAttempts) userObject.loginAttempts = 0
            if (!userObject.locked) userObject.locked = false
            if (!userObject._id) userObject._id = uuid.v4()
            userObject.locked = false
            userObject.emailCode = null
            let returnedUser = userObject

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

            if (!userObject.username) return this.USERNAME_IS_REQUIRED

            if (this.users.find(u => u.username === userObject.username)) return this.USERNAME_ALREADY_EXISTS_TEXT
            if (this.users.find(u => u.email === userObject.email)) return this.EMAIL_ALREADY_EXISTS_TEXT
            this.users.push(userObject);
            return returnedUser;
        } catch (err) {
            console.error(err)
            return undefined

        }

    }

    /**
     * Logs in a user
     * @param {string} username - Username of user
     * @param {string} password - password of user
     * @param {number} twoFactorCode - 2FA code of user or put null if user didn't provide a 2FA
     * @returns {object} - user object with jwt_token, or null if login was unsuccessful, or "User is locked" if user is locked
     * @throws {Error} - any other error
     */
    async login(username, password, twoFactorCode) {
        try {

            const account = this.users.find(u => u.username === username);
            if (account.locked) return this.LOCKED_TEXT
            if (!username) return this.USERNAME_IS_REQUIRED;
            if (!password) return this.PASSWORD_IS_REQUIRED;

            const result = await bcrypt.compare(password, account.password);

            if (!result) {


                if (account.loginAttempts >= this.maxLoginAttempts) {
                    await this.lockUser(account._id)
                    return this.LOCKED_TEXT
                } else {
                    await this.changeLoginAttempts(account._id, account.loginAttempts + 1)
                    return this.INVALID_CREDENTIALS_TEXT
                }
            }
            if (account) {
                if (account.wants2FA) {
                    if (twoFactorCode === undefined) {
                        return this.INVALID_2FA_CODE_TEXT;
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
                await this.changeLoginAttempts(account._id, 0)

                return { ...account, jwt_token };
            }
        } catch (err) {
            console.error(err)
            return undefined
        }
    }
    /**
     * Generates a random string (emailCode) and updates the user object with it
     * @param {string} email - email address of user
     * @returns {string} - emailCode
     * @throws {Error} - any other error
     */
    async registerEmailSignin(email) {
        try {
            const emailCode = Crypto.randomUUID()
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
            return undefined
        }
    }
    /**
     * Verifies a emailCode and returns a valid JWT token for the user
     * @param {string} emailCode - the emailCode to verify
     * @returns {object} - an object with the user info and a valid JWT token
     * @throws {Error} - any error that occurs during the process
     */
    async verifyEmailSignin(emailCode) {
        try {
            if (emailCode === null) return null
            const user = await this.users.find(user => user.emailCode === emailCode);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u.emailCode === emailCode);
            if (userIndex !== -1) {
                this.users[userIndex].emailCode = null;
            }
            const jwt_token = jwt.sign({ _id: user._id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
            this.users.push()
            return { ...user, jwt_token };
        } catch (error) {
            console.error(error)
            return undefined
        }
    }
    /**
     * Retrieves user information based on the user ID
     * @param {string} userId - the user ID to retrieve information
     * @returns {object} - an object with the user information
     * @throws {Error} - any error that occurs during the process
     */
    getInfoFromUser(userId) {
        try {
            const user = this.users.find(u => u._id === userId);
            if (!user) return null;
            return user
        } catch (error) {
            console.error(error)
            return undefined
        }
    }

    /**
     * Retrieves user information based on a custom search criteria
     * @param {string} searchType - the field name to search by (e.g. username, email, etc.).
     *                              It will only find the first element that corresponds to the specified value
     * @param {string} value - the value to match in the specified field
     * @returns {object} - an object with the user information or null if not found
     */
    getInfoFromCustom(searchType, value) {
        try {
            const user = this.users.find(u => u[searchType] === value);
            if (!user) return null;
            return user
        } catch (error) {
            console.error(error)
            return undefined
        }
    }

    setCustomInfo(userId, key, value) {
        try {
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users[userIndex][key] = value;
            }
            this.users.push()
            return this.users[userIndex]
        } catch (error) {
            console.error(error)
            return undefined
        }
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
            console.error(error)
            return undefined
        }
    }
    /**
     * Verifies a 2FA code for a user
     * @param {string} userId - the user ID to verify the 2FA code for
     * @param {string} twofactorcode - the 2FA code to verify
     * @returns {boolean} - true if the code is valid, false otherwise
     */
    async verify2FA(userId, twofactorcode) {
        try {
            let user = this.users.find(user => user._id === userId)
            if (!user) return null
            const verified = speakeasy.totp.verify({
                secret: user.secret2FA,
                encoding: this.OTP_ENCODING,
                token: twofactorcode,
                window: this.OTP_WINDOW
            });
            return verified;
        } catch (error) {
            console.error(error)
            return undefined
        }
    }
    /**
     * Resets the password of a user
     * @param {string} userId - the user ID to reset the password for
     * @param {string} newPassword - the new password to set
     * @returns {object} - the user object after the password has been reset
     * @throws {Error} - any error that occurs during the process
     */
    async resetPassword(userId, newPassword) {
        try {
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
        } catch (error) {
            console.error(error)
            return undefined
        }
    }
    /**
     * Changes the number of login attempts for a user
     * @param {string} userId - the user ID to change the login attempts for
     * @param {number} attempts - the new number of login attempts
     * @returns {object} - the user object after the login attempts have been changed
     * @throws {Error} - any error that occurs during the process
     */
    async changeLoginAttempts(userId, attempts) {
        try {
            const user = this.users.find(u => u._id === userId);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users[userIndex].loginAttempts = attempts;
            }
            this.users.push()

            return user;
        } catch (error) {
            console.error(error)
            return undefined
        }
    }
    /**
     * Locks a user from logging in
     * @param {string} userId - the user ID to lock
     * @returns {object} - the user object after the user has been locked
     * @throws {Error} - any error that occurs during the process
     */
    async lockUser(userId) {
        try {
            const user = this.users.find(u => u._id === userId);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users[userIndex].locked = true;
            }
            this.users.push()

            return user;
        } catch (error) {
            console.error(error)
            return undefined
        }
    }
    /**
     * Unlocks a user from logging in
     * @param {string} userId - the user ID to unlock
     * @returns {object} - the user object after the user has been unlocked
     * @throws {Error} - any error that occurs during the process
     */
    async unlockUser(userId) {
        try {
            const user = this.users.find(u => u._id === userId);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users[userIndex].locked = false;
                this.users[userIndex].loginAttempts = 0;
            }
            this.users.push()
            return user;
        } catch (error) {
            console.error(error)
            return undefined
        }
    }
    /**
     * Revokes all user tokens for a user
     * @param {string} userId - the user ID to revoke all tokens for
     * @returns {undefined}
     * @throws {Error} - any error that occurs during the process
     */
    async revokeUserTokens(userId) {
        try {
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users[userIndex].jwt_version += 1;
            }
            this.users.push()
        } catch (error) {
            console.error(error)
            return undefined
        }
    }
    /**
     * Removes 2FA for a user
     * @param {string} userId - the user ID to remove 2FA for
     * @returns {object} - the user object after 2FA has been removed
     * @throws {Error} - any error that occurs during the process
     */
    async remove2FA(userId) {
        try {
            const user = this.users.find(u => u._id === userId);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users[userIndex].wants2FA = false;
                user.wants2FA = false;
                this.users[userIndex].secret2FA = "";
                user.secret2FA = false;
                this.users[userIndex].qrCode = "";
                user.qrCode = false;
            }
            this.users.push();

            return user;
        } catch (error) {
            console.error(error);
            return undefined;
        }
    }
    /**
     * Adds 2FA for a user
     * @param {string} userId - the user ID to add 2FA for
     * @returns {object} - the user object after 2FA has been added
     * @throws {Error} - any error that occurs during the process
     */
    async add2FA(userId) {
        try {
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
        } catch (error) {
            console.error(error)
            return undefined
        }
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
            console.error(error)
            return undefined
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
     * @param {object} token - the JWT token from the user
     * @returns {boolean} - true if the token is valid, otherwise false
     * @throws {Error} - any error that occurs during the process
     */
    async isAuthenticated(token) {
        try {
            let user = await this.verifyToken(token)
            console.log(user)
            if (!token) {
                return false;
            }
            if (!user) {
                return false;
            }
            return user
        } catch (err) {
            console.log(err)
            return false
        }
    }

}

module.exports = Authenticator
