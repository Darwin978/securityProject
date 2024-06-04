const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user.js')
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const UserDb = require('./mondodb.js')
const { check, validationResult } = require('express-validator');

const app = express();

app.use(express.json())

app.get('/', (req, res)=>{
    res.send("HOLA MUNDO")
})



app.listen(3000, ()=>{console.log("PROYECTO UP")})

app.use('/admin', checkRole('admin'))
app.use('/user', checkRole("user"))

function checkRole(role){
    return (req, res, next) =>{
        if(req.user && req.user.role ===role){
            next();
        }else{
            res.status(403).json({message:'Forbidden'});
        }
    }
}

passport.use(new LocalStrategy(
    function(user, password, done){
        User.findOne({user:user}, function(err, user){
            if(err) {return done(err);}
            if(!user) {return done(null, false, {message: 'Incorrrect username'});}
            if(!user.verifyPassword(password)) {return done(null, false, {message: "Incorrect password"});}
            return done(null, user);
        });
    }
));

app.get('/register', (req, res) => {

    const secret = speakeasy.generateSecret();
    QRCode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
        if(err || !dataUrl)
            return reject(err)
        res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Imagen Base64</title>
    </head>
    <body>
      <img src="`+dataUrl+`">
      <h2> secret: `+secret.base32+`</h2>

    </body>
    </html>
  `)
    });

    
});


app.post("/login", passport.authenticate('local', {failureRedirect:'/login'}), (req, res)=>{
    
    res.redirect('/dashboard')
});

app.get("/validate/:token/:secret", (req, res) => {
    const { token, secret } = req.params;

    try {
        const tokenValidates = speakeasy.totp.verify({
            secret,
            encoding: 'base32',  // Verifica si tu secreto está en base32.
            token
        });

        res.json({ valid: tokenValidates });
    } catch (error) {
        // Manejo de errores adecuado para evitar el envío de múltiples respuestas.
        if (!res.headersSent) {
            res.status(400).json({ error: 'Invalid token or secret' });
        }
    }
});

app.post('/createUser', async (req, res) => {
    const user = new UserDb({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password
    });
    try {
    const newUser = await user.save();
    res.status(201).json(newUser);
    } catch (err) {
    res.status(400).json({ message: err.message });
    }
});

// STEP 6
app.post("/register2.0", [
    check("username").isAlphanumeric().withMessage("Username must be alphanumeric"),
    check("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    check("email").isEmail().withMessage("Must be a valid email"),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const user = new UserDb(req.body);
        await user.save();
        res.status(201).json(user);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});