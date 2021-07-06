function start(choice, email, password) {
    // const users = [{ email: 'penson.mathys@gmail.com', password: 'mathys' }];
	const users = [];
    if (choice === 'undefined') return console.log("You didn't fill in a choice");
    if (email === 'undefined') return console.log("You didn't fill in an email");
    if (password === 'undefined') return console.log("You didn't fill in password");

    if (choice === 'login') {
		let sleep = ms => new Promise(resolve => setTimeout(resolve, 1000));
		sleep(3)
        const user = users.find((user) => user.email === email);
        if (user == null) {
            return console.log('Cannot find user');
        }
        try {
            if (password === user.password) {
                console.log(`The user with email ${user.email} is logged in`);
            } else {
                console.log('Not Allowed');
            }
        } catch (err) {
            console.log(err)
        }
    }
    if (choice === 'register') {
        try {
            const user = { email, password };
            users.push(user);
            console.log(`User ${user.email} is created`);
            console.log(users);
        } catch (err) {
            console.log(err);
        }
    }
}

module.exports = start;