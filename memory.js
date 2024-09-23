// DB Is in memory, can dumped using console.log(auth.users) to see all user objects in auth.users
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')
const { nanoid } = require('nanoid');

class Authenticator {
    constructor(QR_LABEL, rounds, JWT_SECRET_KEY, JWT_OPTIONS, maxLoginAttempts, userObject) {
        this.QR_LABEL = QR_LABEL;
        this.rounds = rounds;
        this.users = userObject;
        this.JWT_SECRET_KEY = JWT_SECRET_KEY;
        this.JWT_OPTIONS = JWT_OPTIONS;
        this.maxLoginAttempts = maxLoginAttempts - 2;
    }

    async register(userObject) {
        if (!userObject.loginAttempts) userObject.loginAttempts = 0
        if (!userObject.locked) userObject.locked = false
        if (!userObject._id) userObject._id = uuid.v4()
        let returnedUser = userObject
        try {
            const hash = await bcrypt.hash(userObject.password, this.rounds);
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
        const account = this.users.find(u => u.email === email);
        if (!email) return null;
        if (!password) return null;

        try {
            if (account.locked) return "User is locked"
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
                        encoding: 'base32',
                        token: twoFactorCode, // Verwijder Number()
                        window: 2 // Sta 2 tijdstippen toe voor en na de huidige tijd
                    });
                    if (!verified) return "Invalid 2FA code";

                }
                const jwt_token = jwt.sign({ _id: account._id, version: account.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
                this.changeLoginAttempts(account._id, 0)

                return { ...account, jwt_token };
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
        const jwt_token = jwt.sign({ _id: user._id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
        return { ...user, jwt_token };
    }
    getInfoFromUser(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        return user
    }

    async verifyToken(token) {
        if (jwt.verify(token, this.JWT_SECRET_KEY, this.JWT_OPTIONS)) {
            let jwt_token = jwt.decode(token);
            return (this.getInfoFromUser(jwt_token._id).jwt_version == jwt_token.version);
        }
    }
    async verify2FA(userId, twofactorcode) {
        let user = this.users.find(user => user._id === userId)
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
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        user.password = await bcrypt.hash(newPassword, this.rounds);
        // Vervang het wachtwoord van de gebruiker in de array
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].password = user.password;
            this.users[userIndex].jwt_version += 1
        }
        return user;
    }
    async changeLoginAttempts(userId, attempts) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].loginAttempts = attempts;
        }
        return user;
    }
    async lockUser(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].locked = true;
        }
        return user;
    }
    async unlockUser(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].locked = false;
        }
        return user;
    }
    async revokeUserTokens(userId) {
        const userIndex = this.users.findIndex(u => u._id === userId);
        if (userIndex !== -1) {
            this.users[userIndex].jwt_version += 1;
        }

    }
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
        return user;
    }
    async add2FA(userId) {
        const user = this.users.find(u => u._id === userId);
        if (!user) return null;
        const userIndex = this.users.findIndex(u => u._id === userId);
        const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
        const otpauth_url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: this.QR_LABEL,
            encoding: 'base32'
        });
        const qrCode = await QRCode.toDataURL(otpauth_url);
        if (userIndex !== -1) {
            this.users[userIndex].wants2FA = true;
            user.wants2FA = true
            this.users[userIndex].secret2FA = secret.base32;
            user.secret2FA = secret.base32
            user.qrCode = qrCode
        }
        return user;
    }
    async removeUser(userId) {
        try {
            const user = this.users.find(u => u._id === userId);
            if (!user) return null;
            const userIndex = this.users.findIndex(u => u._id === userId);
            if (userIndex !== -1) {
                this.users.splice(userIndex, 1);
            }
            return "User has been removed"

        } catch (error) {
            return `User with ID ${userId} couldn't be removed`

        }

    }
    async dumpDB() {
        return this.users
    }

}

module.exports = Authenticator