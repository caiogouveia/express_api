const express = require('express');
const sqlite3 = require('sqlite3');
const session = require('express-session');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const expressJWt = require('express-jwt');

const bodyParser = require('body-parser');
const app = express();
const port  = 3000;

app.set('view engine', 'ejs');
app.use(session({secret: 'secret'}))
app.use(bodyParser.urlencoded({extended: false}));

// intial DB create
const db = new sqlite3.Database('db.sqlite');
db.serialize(()=>{
    db.run('CREATE TABLE IF NOT EXISTS `users` (`user_id` INTEGER PRIMARY KEY AUTOINCREMENT, `email` VARCHAR(255) NOT NULL, `secret` varchar(255) NOT NULL)')
});
db.close();


// sign up page
app.get("/", (req, res) => {
  res.render('signup.ejs');
});

// Sign up post
app.post('sign-up', (request, response)=>{
    const email = request.body.email;
    const secret = authenticator.generateSecret();
    const db = new sqlite3.Database('db.sqlite');
    db.serialize(()=>{
        db.run('INSERT INTO `users`(`email`, `secret`) VALUES (?, ?)',
        [secret, email],
        (err) => {
            if (err){
                throw err;
            }
            QRCode.toDataURL(authenticator.keyuri(email, 'otp-app', secret), (err, url) => {
                if(err){
                    throw err;
                }
                request.session.qr = url;
                request.session.email = email;
                response.redirect('/sign-up-2fs');
            });
        });
    });
});

app.listen(port, () => {
  console.log('Server started.');
  }
)
