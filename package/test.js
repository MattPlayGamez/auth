const Authenticator = require('./index')
const auth = new Authenticator()

const email = 'test@example.mail'
const password = 'example'

setTimeout(async () => {
    const user = await auth.register(email, password)
    // console.log(user)
}, 10);

setTimeout(() => {
    const account = auth.login(email, password)
    console.log(account);
}, 500);

// setTimeout(async () => {
//     const all =  await auth.all()
//     console.log(all)
// }, 1000);