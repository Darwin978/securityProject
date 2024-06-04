const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user.js')
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const UserDb = require('./mondodb.js')
const { check, validationResult } = require('express-validator');
const crypto = require('crypto');

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
    const out = "otpauth://totp/SecretKey?secret=LYVDS6K2KQ3EGTBKGV3XOT3GOBAV4IKAN5GX2TDQK5WV2WBKNY2Q";
    QRCode.toDataURL(out, (err, dataUrl) => {
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
    </body>
    </html>
  `)
    });

    
});


app.post("/login", passport.authenticate('local', {failureRedirect:'/login'}), async (req, res)=>{
    const userToCreate = {
        username : String,
        password : String,
        email : String
    };
    
    userToCreate.username = req.body.username;
    userToCreate.password = encriptar(req.body.password);
    userToCreate.email = req.body.email;

    const existingUser = await UserDb.findOne({ $or: [ userToCreate ] });
    if (existingUser) {
        return res.status(400).json({ message: 'Usuario logeado' });
    }
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

const secretKey = crypto.createHash('sha256').update(String("my_static_secret_key")).digest('base64').substr(0, 32); // Clave de 256 bits
const iv = crypto.randomBytes(16); // IV de 16 bytes


function encriptar(text) {
    try {
        console.log("lleha"+iv);
        const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    } catch (error) {
        console.error('Error encriptando el texto:', error);
        throw error; // O manejar el error de acuerdo a tus necesidades
    }
}

app.post("/login2.0", [
    check("username").isAlphanumeric().withMessage("Usuario invalido"),
    check("password").isLength({ min: 6 }).withMessage("La contraseña es demasiado corta"),
    check("email").isEmail().withMessage("El email es invalido"),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { username, password, email } = req.body;
        console.log(username)
        const encryptedPassword = encriptar(password); // Encripta la contraseña
        console.log(encryptedPassword)
        const user = new UserDb({ username, password: encryptedPassword, email });
        
        const existingUser = await UserDb.findOne({ $or: [ user ] });
        if (existingUser) {
            return res.status(400).json({ message: 'Usuario logeado' });
        }else{
            return res.status(400).json({ message: 'No existe el usuario' });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});




// Función para desencriptar
function desencriptar(encryptedText) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

app.post("/register3.0", [
    check("username").isAlphanumeric().withMessage("Username must be alphanumeric"),
    check("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    check("email").isEmail().withMessage("Must be a valid email"),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        // VALIDA USER REQUEST
        const username = req.header('username');
        if (!username) {
            return res.status(400).json({ message: 'Username is required in the header' });
        }

        const password = req.header('password');
        if (!password) {
            return res.status(400).json({ message: 'Password is required in the header' });
        }

        const email = req.header('email');
        if (!email) {
            return res.status(400).json({ message: 'Email is required in the header' });
        }

        // Verificar si el usuario que hace la peticion existe
        const existingUserRequest = await UserDb.findOne({ $or: [{ username }, { password }, { email }] });
        if (existingUserRequest) {
            // Validar permiso
            //return res.status(400).json({ message: 'El usuario no tiene los permisos para crear registros' });
        }

        // Verificar si el usuario o el correo que quiero crear ya existen
        const userToCreate = {
            username : String,
            password : String,
            email : String
        };
        
        userToCreate.username = req.body.username;
        userToCreate.password = encriptar(req.body.password);
        userToCreate.email = req.body.email;

        const existingUser = await UserDb.findOne({ $or: [ userToCreate ] });
        if (existingUser) {
            return res.status(400).json({ message: 'Username or email already exists' });
        }

        const user = new UserDb(userToCreate);
        await user.save();
        res.status(201).json(user);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


