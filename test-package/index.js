const start = require('../package/start.js')
const readline = require('readline')


const email = 'penson.mathys@gmail.com'
const password = 'mathys'


start('register', email, password)

start('login', email, password)