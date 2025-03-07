const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');


const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({ secret: 'secret', resave: true, saveUninitialized: true }));
// Utilisez express.static pour servir des fichiers statiques à partir du dossier 'public'
app.use(express.static(path.join(__dirname, 'frontend')));

// Route pour servir un fichier HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

const db = mysql.createConnection({
    host: 'db',  // use 'db' because it is the service name in your Docker Compose file
    user: 'user',
    password: 'password', 
    database: 'vulnerable_db',
    port: '3306'  // MySQL container's internal port
});
db.connect();

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        if (results.length > 0) {
            // Connexion réussie, sauvegarder l'utilisateur dans la session
            req.session.user = username;

            // Redirection vers la page de profil
            res.redirect(`/profile/${username}`);
        } else {
            res.send('Invalid credentials');
        }
    });
});

// Route de la page de profil
app.get('/profile/:username', (req, res) => {
    const { username } = req.params;

    // Vérifier si l'utilisateur est connecté en vérifiant la session
    if (!req.session.user || req.session.user !== username) {
        return res.status(401).send('You must be logged in to view this page');
    }

    // Si l'utilisateur est connecté, renvoyer la page profile.html
    res.sendFile(path.join(__dirname, 'frontend', 'profile.html')); // Assurez-vous que le fichier profile.html existe
});
app.post('/logout', (req, res) => {
    // Supprimer la session pour déconnecter l'utilisateur
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error during logout');
        }

        // Rediriger l'utilisateur vers la page de connexion ou la page d'accueil
        res.sendFile(path.join(__dirname, 'frontend', 'login.html')); // Assurez-vous que le fichier profile.html existe
    });
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`; 
    db.query(query, (err, results) => {
        res.send('User registered!');
    });
});
app.get('/users', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        res.json(results); 
    });
});


app.listen(3000, () => console.log('Vulnerable app running on port 3000'));
