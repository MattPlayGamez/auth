// A WIP

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const speakeasy = require('speakeasy')
const QRCode = require('qrcode')
const mongoose = require('mongoose')
const { nanoid } = require('nanoid');



// Creëer het gebruikersmodel

class Authenticator {
    constructor(QR_LABEL, salt, JWT_SECRET_KEY, JWT_OPTIONS, maxLoginAttempts, MONGODB_CONNECTION_STRING, userSchema) {
        this.QR_LABEL = QR_LABEL;
        this.salt = salt;
        this.JWT_SECRET_KEY = JWT_SECRET_KEY;
        this.JWT_OPTIONS = JWT_OPTIONS;
        this.maxLoginAttempts = maxLoginAttempts;

        // Verbind met MongoDB
        mongoose.connect(MONGODB_CONNECTION_STRING, { useNewUrlParser: true, useUnifiedTopology: true });

        this.User = mongoose.model('User', userSchema)
    }

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
                    encoding: 'base32'
                });
                const qrCode = await QRCode.toDataURL(otpauth_url);
                newUser.secret2FA = secret.base32;
                await newUser.save();
                return { user: newUser, qrCode }
            }
            await newUser.save();


            if (!userObject.wants2FA) {
                return { user: newUser };
            }

        } catch (err) {
            if (err.code === 11000) {
                return "Gebruiker bestaat al";
            }
            console.log(err);
            throw err;
        }
    }

    async login(email, password, twoFactorCode) {
        const user = await this.User.findOne({ email });
        if (!user) return null;

        try {
            if (user.locked) return "User is locked"
            const result = await bcrypt.compare(password, user.password);
            if (!result) {
                console.log(`${user.loginAttempts} >= ${this.maxLoginAttempts}`)

                if (user.loginAttempts >= this.maxLoginAttempts) {

                    this.lockUser(user._id);
                } else {
                    console.log("changing login attempts")
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
                            encoding: 'base32'
                        });
                        const qrCode = await QRCode.toDataURL(otpauth_url);
                        return { qrCode };
                    }

                    const verified = speakeasy.totp.verify({
                        secret: user.secret2FA,
                        encoding: 'base32',
                        token: twoFactorCode,
                        window: 2 // Sta 2 tijdstippen toe voor en na de huidige tijd
                    });
                    console.log('Verification result:', verified);
                    if (!verified) return "Invalid 2FA code";

                }
                const jwt_token = jwt.sign({ id: user._id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);

                this.changeLoginAttempts(user._id, 0)

                return { ...user.toObject(), jwt_token };
            }
        } catch (err) {
            throw err;
        }
    }
    async registerEmailSignin(email) {
        let emailCode = nanoid(20)
        try {
            await this.User.findOneAndUpdate({ email: email }, { emailCode: emailCode })
            return emailCode;

        } catch (error) {
            console.error(error)
        }
    }
    async verifyEmailSignin(emailCode) {
        if (emailCode === null) return null

        const user = await this.User.findOne({ emailCode: emailCode });
        if (!user) return null;
        await this.User.findOneAndUpdate({ emailCode: emailCode }, { emailCode: null })
        const jwt_token = jwt.sign({ id: user._id, version: user.jwt_version }, this.JWT_SECRET_KEY, this.JWT_OPTIONS);
        return { ...user, jwt_token };
    }
    async getInfoFromUser(userId) {
        return await this.User.findOne({ _id: userId });
    }

    async verifyToken(token) {
        if (jwt.verify(token, this.JWT_SECRET_KEY, this.JWT_OPTIONS)) {
            let jwt_token = jwt.decode(token);
            console.log(jwt_token)
            let user = await this.getInfoFromUser(jwt_token.id)

            if (user.jwt_version == jwt_token.version) {
                return true
            } else {
                return false
            }
        }
    }
    async verify2FA(userId, twofactorcode) {
        let user = await this.User.findOne({ _id: userId })
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
        this.revokeUserTokens(userId)
        const hash = await bcrypt.hash(newPassword, this.salt);
        return await this.User.findOneAndUpdate({ _id: userId }, { password: hash }, { new: true })

    }
    async changeLoginAttempts(userId, attempts) {
        return await this.User.findOneAndUpdate({ _id: userId }, { loginAttempts: attempts }, { new: true });
    }
    async lockUser(userId) {
        return await this.User.findOneAndUpdate({ _id: userId }, { locked: true }, { new: true });
    }
    async unlockUser(userId) {
        return await this.User.findOneAndUpdate({ _id: userId }, { locked: false }, { new: true });
    }

    async revokeUserTokens(userId) {
        let newVersion = (await this.User.findOne({ _id: userId })).jwt_version + 1
        return await this.User.findOneAndUpdate({ _id: userId }, { jwt_version: newVersion }, { new: false });
    }
    async remove2FA(userId) {
        return await this.User.findOneAndUpdate(
            { _id: userId },
            { wants2FA: false, secret2FA: "", qrCode: "" },
            { new: true }
        );
    }
    async add2FA(userId) {
        const user = await this.User.findOne({ _id: userId });
        if (!user) return null;

        const secret = speakeasy.generateSecret({ name: this.QR_LABEL });
        const otpauth_url = speakeasy.otpauthURL({
            
            secret: secret.base32,
            label: this.QR_LABEL,
            encoding: 'base32'
        });
        const qrCode = await QRCode.toDataURL(otpauth_url);

        return await this.User.findOneAndUpdate(
            { _id: userId },
            { wants2FA: true, secret2FA: secret.base32, qrCode },
            { new: true }
        );
    }
    async removeUser(userId) {
        try {
        await this.User.findOneAndDelete({ _id: userId });
            return "User has been removed"
        } catch (error) {
            return `User with ID ${userId} couldn't be removed`
        }
    }
    async users() {
        return await this.User.find()
    }

}

module.exports = Authenticator