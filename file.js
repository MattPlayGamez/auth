// Local file is not written to disk
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')
const fs = require('fs');
const crypto = require('crypto');
// const { nanoid } = require('nanoid');
import { nanoid } from 'nanoid'

const algorithm = 'aes-256-ctr';



// Helper functions
function encrypt(text, password) {
    const salt = crypto.randomBytes(16);
    const key = crypto.scryptSync(password, salt, 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let crypted = cipher.update(text, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return salt.toString('hex') + iv.toString('hex') + crypted;
}

function decrypt(encryptedText, password) {
    const salt = Buffer.from(encryptedText.slice(0, 32), 'hex');
    const iv = Buffer.from(encryptedText.slice(32, 64), 'hex');
    const key = crypto.scryptSync(password, salt, 32);
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
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
    constructor(QR_LABEL, salt, JWT_SECRET_KEY, JWT_OPTIONS, maxLoginAttempts, DB_FILE_PATH, DB_PASSWORD) {
        this.QR_LABEL = QR_LABEL;
        this.salt = salt;
        this.JWT_SECRET_KEY = JWT_SECRET_KEY;
        this.JWT_OPTIONS = JWT_OPTIONS;
        this.maxLoginAttempts = maxLoginAttempts - 2;
        this.users = loadUsersFromFile(DB_FILE_PATH, DB_PASSWORD);
        this.DB_FILE_PATH = DB_FILE_PATH
        this.DB_PASSWORD = DB_PASSWORD

        // Override methods to update file when users array changes
        const originalPush = this.users.push;
        this.users.push = (...args) => {
            const result = originalPush.apply(this.users, args);
            console.log("database changed")
            saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);
            return result;
        };

    }



    async register(userObject) {
        if (!userObject.loginAttempts) userObject.loginAttempts = 0
        if (!userObject.locked) userObject.locked = false
        if (!userObject.id) userObject.id = uuid.v4()
        try {
            let returnedUser = userObject
            const hash = await bcrypt.hashSync(userObject.password, this.salt);
            if (userObject.wants2FA) {
                const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
                const otpauth_url = speakeasy.otpauthURL({
                    secret: secret.base32,
                    label: this.QR_LABEL,
                    encoding: 'base32'
                });
                const qrCode = await QRCode.toDataURL(otpauth_url);
                userObject.secret2FA = secret.base32;
                returnedUser.qrCode = qrCode;
            }
            returnedUser.password = hash;
            userObject.password = hash;
            userObject.jwt_version = 1

            if (this.users.find(u => u.email === userObject.email)) return "User already exists"
            this.users.push(userObject);
            return returnedUser;
        } catch (err) {
            console.log(err)
        }

    }

    async login(email, password, twoFactorCode) {
        const user = this.users.find(u => u.email === email);
        if (!user) return null;

        try {
            if (user.locked) return "User is locked"
            const result = await bcrypt.compareSync(password, user.password);

            if (!result) {

                (user.loginAttempts >= this.maxLoginAttempts) ? this.lockUser(user.id) : await this.changeLoginAttempts(user.id, user.loginAttempts + 1)

                return null
            };
            if (user) {
                if (user.wants2FA) {
                    if (twoFactorCode === undefined) {
                        return null;
                    }


                    const verified = speakeasy.totp.verify({
                        secret: user.secret2FA,
                        encoding: 'base32',
                        token: twoFactorCode, // Verwijder Number()
                        window: 2 // Sta 2 tijdstippen toe voor en na de huidige tijd
                    });
                    console.log('Verification result:', verified);
                    if (!verified) return "Invalid 2FA code";

                }
                const jwt_token = jwt.sign({ id: user.id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
                this.changeLoginAttempts(user.id, 0)

                return { ...user, jwt_token };
            }
        } catch (err) {
            throw err;
        }
    }
    async registerEmailSignin(email) {
        let emailCode = nanoid(20)
        try {
            const user = this.users.find(u => u.email === email);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u.email === email);
            if (userIndex !== -1) {
                this.users[userIndex].emailCode = emailCode;
            }
            return emailCode;

        } catch (error) {
            console.error(error)
        }
    }
    async verifyEmailSignin(emailCode) {
        if (emailCode === null) return null
        const user = await this.users.find(user => user.emailCode == emailCode);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.emailCode === emailCode);
        if (userIndex !== -1) {
            this.users[userIndex].emailCode = null;
        }
        const jwt_token = jwt.sign({ id: user.id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
        return { ...user, jwt_token };
    }
    getInfoFromUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        return user
    }

    //jwt_version
    async verifyToken(token) {
        if (jwt.verify(token, this.JWT_SECRET_KEY, this.JWT_OPTIONS)) {
            let jwt_token = jwt.decode(token);
            console.log(jwt_token)
            console.log(this.getInfoFromUser(jwt_token.id).jwt_version)
            return (this.getInfoFromUser(jwt_token.id).jwt_version == jwt_token.version);
        }
    }
    async verify2FA(userId, twofactorcode) {
        let user = this.users.find(user => user.id === userId)
        if (!user) return null
        const verified = speakeasy.totp.verify({
            secret: user.secret2FA,
            encoding: 'base32',
            token: twofactorcode,
            window: 2 // Sta 2 tijdstippen toe voor en na de huidige tijd
        });
        return verified;

    }
    async resetPassword(userId, newPassword) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        user.password = bcrypt.hashSync(newPassword, this.salt);
        // Vervang het wachtwoord van de gebruiker in de array
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].password = user.password;
            this.users[userIndex].jwt_version += 1
        }
        saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);

        return user;
    }
    async changeLoginAttempts(userId, attempts) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].loginAttempts = attempts;
        }
        saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);
        return user;
    }
    async lockUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].locked = true;
        }
        saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);
        return user;
    }
    async unlockUser(userId) {
        console.log(userId)
        console.log(this.users)
        const user = this.users.find(u => u.id === userId);
        // console.log(user)
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].locked = false;
        }
        saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);
        return user;
    }

    async revokeUserTokens(userId) {
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].jwt_version += 1;
        }

    }

    async remove2FA(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].wants2FA = false;
            user.wants2FA = false
            this.users[userIndex].secret2FA = "";
            user.secret2FA = false
            this.users[userIndex].qrCode = "";
            user.qrCode = false
        }
        saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);
        return user;
    }
    async add2FA(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
        const otpauth_url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: this.QR_LABEL,
            encoding: 'base32'
        });
        const qrCode = await QRCode.toDataURL(otpauth_url);
        userObject.secret2FA = secret.base32;
        returnedUser.qrCode = qrCode;
        if (userIndex !== -1) {
            this.users[userIndex].wants2FA = true;
            user.wants2FA = true
            this.users[userIndex].secret2FA = secret;
            user.secret2FA = secret
            user.qrCode = otpauth_url
        }
        saveUsersToFile(this.users, this.DB_FILE_PATH, this.DB_PASSWORD);
        return user;
    }
    async removeUser(userId) {
        try {
            const user = this.users.find(u => u.id === userId);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u.id === userId);
            if (userIndex !== -1) {
                this.users.splice(userIndex, 1);
            }
            "User has been removed"

        } catch (error) {
            return `User with ID ${userId} couldn't be removed`

        }

    }
}







module.exports = Authenticator