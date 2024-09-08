const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')

class Authenticator {
    constructor(QR_LABEL, salt, JWT_SECRET_KEY, JWT_OPTIONS, maxLoginAttempts, userObject) {
        this.QR_LABEL = QR_LABEL;
        this.salt = salt;
        this.users = userObject;
        this.JWT_SECRET_KEY = JWT_SECRET_KEY;
        this.JWT_OPTIONS = JWT_OPTIONS;
        this.maxLoginAttempts = maxLoginAttempts - 2;
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
                userObject.SECRET2FA = secret.base32;
                returnedUser.qrCode = qrCode;
            }
            returnedUser.password = hash;
            userObject.password = hash;

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
                        secret: user.SECRET2FA,
                        encoding: 'base32',
                        token: twoFactorCode, // Verwijder Number()
                        window: 2 // Sta 2 tijdstippen toe voor en na de huidige tijd
                    });
                    console.log('Verification result:', verified);
                    if (!verified) return "Invalid 2FA code";

                }
                const jwt_token = jwt.sign({ id: user.id }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
                this.changeLoginAttempts(user.id, 0)

                return { ...user, jwt_token };
            }
        } catch (err) {
            throw err;
        }
    }
    getInfoFromUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        return user
    }

    async verifyToken(token) {
        return jwt.verify(token, this.JWT_SECRET_KEY, this.JWT_OPTIONS)
    }
    async resetPassword(userId, newPassword) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        user.password = bcrypt.hashSync(newPassword, this.salt);
        // Vervang het wachtwoord van de gebruiker in de array
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].password = user.password;
        }
        return user;
    }
    async changeLoginAttempts(userId, attempts) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].loginAttempts = attempts;
        }
        return user;
    }
    async lockUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].locked = true;
        }
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
        return user;
    }
    async remove2FA(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].wants2FA = false;
            user.wants2FA = false
            this.users[userIndex].SECRET2FA = "";
            user.SECRET2FA = false
            this.users[userIndex].qrCode = "";
            user.qrCode = false
        }
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
        userObject.SECRET2FA = secret.base32;
        returnedUser.qrCode = qrCode;
        if (userIndex !== -1) {
            this.users[userIndex].wants2FA = true;
            user.wants2FA = true
            this.users[userIndex].SECRET2FA = secret;
            user.SECRET2FA = secret
            user.qrCode = otpauth_url
        }
        return user;
    }
    async removeUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
            this.users.splice(userIndex, 1);
        }
        return user;
    }

}

module.exports = Authenticator