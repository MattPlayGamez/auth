import Authenticator from "../mongodb.js";

let DB_SCHEMA = {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    loginAttempts: { type: Number, default: 0 },
    locked: { type: Boolean, default: false },
    wants2FA: { type: Boolean, default: false },
    secret2FA: String
}


let connectionString = "CONNECTIONSTRING" // The connection string for MongoDB
const auth = new Authenticator('MyApp', 12, 'your_jwt_secret', { expiresIn: '1 ' }, 5, connectionString, DB_SCHEMA);
