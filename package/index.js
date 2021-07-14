class Authenticator {
    users = [];
    test() {
        console.log('Test Passed');
    }
    async register(email, password) {
        const bcrypt = require('bcrypt')
        this.email = email;
        this.password = password;
        const hashedPassword = await bcrypt.hash(password, 12)
        const user = { email: email, password: hashedPassword };
        this.users.push(user);
    }

    login(email, password) {
        const bcrypt = require('bcrypt')
        this.email = email;
        this.password = password;
        const user = this.users.find(user => user.email === email)
        if (!user) return console.log('Didn\'t found the email')
        if (!bcrypt.compareSync(password, user.password)) return console.log('Password isn\'t right')
        return true
    };
    all() {
        console.log(this.users);
    }

};


module.exports = Authenticator;