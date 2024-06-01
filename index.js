const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user.js')
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const UserDb = require('./mondodb.js')

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
        res.json({ secret: secret.base32, qrCode: dataUrl})
    });
})


app.post("/login", passport.authenticate('local', {failureRedirect:'/login'}), (req, res)=>{
    
    res.redirect('/dashboard')
})

app.get("/validate/:token/:secret", (req, res) => {
    const { token, secret } = req.params;
    const tokenValidates = speakeasy.totp.verify({
        secret,
        encoding: 'base64',
        token
    });
    res.json( tokenValidates );
})

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