class Authenticator {
    users = [];
    test() {
        console.log('Test Passed');
    }
    async register(email, password) {
        const bcrypt = require('bcrypt')
        const { nanoid } = require('nanoid')
        const id = nanoid(15)
        this.email = email;
        this.password = password;
        const hashedPassword = await bcrypt.hash(password, 12)
        const user = { id: id, email: email, password: hashedPassword };
        this.users.push(user);
        // console.log(this.users)
        return user
    }

    login(email, password) {
        const bcrypt = require('bcrypt')
        this.email = email;
        this.password = password;
        const account = this.users.find(user => email === user.email)
        if(account == null) return 'Nothing Found'
        if (email !== account.email) return 'invalid email'
        if (!bcrypt.compareSync(password, account.password)) return 'invalid password'
        return account
    };
    all() {
        return this.users
    }
};


module.exports = Authenticator;