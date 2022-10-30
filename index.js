const express = require('express');
const sqlite3 = require('sqlite3');
const session = require('express-session');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');
const { expressjwt } = require("express-jwt");

const bodyParser = require('body-parser');
const app = express();
const port  = 3000;

app.set('view engine', 'ejs');
app.use(session({secret: 'secret'}));
app.use(bodyParser.urlencoded({extended: false}));

// intial DB create
const db = new sqlite3.Database('db.sqlite');
db.serialize(()=>{
    db.run('CREATE TABLE IF NOT EXISTS `users` (`user_id` INTEGER PRIMARY KEY AUTOINCREMENT, `email` VARCHAR(255) NOT NULL, `secret` varchar(255) NOT NULL)')
});
db.close();

function verifyLogin (email, code, req, res, failUrl) {
    //load user by email
    console.log('###############################');
    console.log('VERIFY LOGIN');
    console.log('###############################');
    // const db = new sqlite3.Database('db.sqlite')
    db.serialize(() => {
      db.get('SELECT secret FROM users WHERE email = ?', [email], (err, row) => {
        if (err) {
          throw err
        }

        if (!row) {
          console.log('user not found');
          return res.redirect('/')
        }

        if (!authenticator.check(code, row.secret)) {
          console.log("authenticador não valida, secret e code");
          console.log(JSON.stringify(row));
          //redirect back
          return res.redirect(failUrl)
        }

        //correct, add jwt to session
        req.session.qr = null
        req.session.email = null
        req.session.token = jwt.sign(email, 'secret')

        //redirect to "private" page
        return res.redirect('/private')
      });
    });
}

const jwtMiddleware = expressjwt({
    secret: 'supersecret',
    algorithms: ['HS256'],
    getToken: (req) => {
        return req.session.token
    }
});

// sign up page
app.get("/", (req, res) => {
  res.render('signup.ejs');
});

// Sign up post
app.post('/sign-up', (request, response)=>{
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
                response.redirect('/sign-up-2fa');
            });
        });
    });
});

// sign-up-2fa
app.get('/sign-up-2fa', (req, res) => {
    if (!req.session.qr) {
        return res.redirect('/')
    }

    return res.render('signup-2fa.ejs', { qr: req.session.qr })
});

// post sign-up-2fa
app.post('/sign-up-2fa', (req, res) => {
    if (!req.session.email) {
        return res.redirect('/')
    }

    const email = req.session.email,
        code = req.body.code

    return verifyLogin(email, code, req, res, '/sign-up-2fa')
});

// login page
app.get('/login', (req, res) => {
    return res.render('login.ejs')
});

// post login
app.post('/login', (req, res) => {
    //verify login
    const email = req.body.email,
        code = req.body.code

    return verifyLogin(email, code, req, res, '/login')
});

// Provate pate
app.get('/private', jwtMiddleware, (req, res) => {
    return res.render('private.ejs', { email: req.user })
});

// logout page
app.get('/logout', jwtMiddleware, (req, res) => {
    req.session.destroy();
    return res.redirect('/');
});

app.listen(port, () => {
    console.log('Server started.');
});
