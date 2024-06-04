const mongoose = require('mongoose');

const dbURI = 'mongodb://localhost:27017/databaseExample';
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Conectado a la base de datos MongoDB');
    })
.catch((err) => {
    console.error('Error al conectar a la base de datos MongoDB:', err);
});

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
    type: String,
    required: true
    }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
module.exports = User; 