const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const helmet = require('helmet');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({ secret: 'secret', resave: true, saveUninitialized: true }));
app.use(express.static(path.join(__dirname, 'frontend')));

  app.use(helmet({
    contentSecurityPolicy: false,
    xssFilter: false // Désactiver XSS Protection
  }));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

const db = mysql.createConnection({
    host: 'db',  
    user: 'user',
    password: 'password', 
    database: 'vulnerable_db',
    port: '3306'  
});
db.connect();

app.post('/login', (req, res) => {
    res.setHeader('X-XSS-Protection', '0');  // Désactiver la protection XSS

    const { email, password } = req.body;

    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send('Database error');
        }

        if (results.length > 0) {
            req.session.user= results[0].id;
            console.log(req.session.user)
            res.redirect(`/profile/${results[0].id}`);
        } else {
            res.send('Invalid credentials');
        }
    });
});

app.get('/profile/:id', (req, res) => {
    res.setHeader('X-XSS-Protection', '0');  // Désactiver la protection XSS

    const { id } = req.params;

    if (!req.session.user || req.session.user != id) {
        return res.status(401).send('You must be logged in to view this page');
    }

    // Récupérer les informations de l'utilisateur
    const query = `SELECT * FROM users WHERE id = '${id}'`;
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send('Error fetching user data');
        }
        const user = results[0];
     res.sendFile(path.join(__dirname, 'frontend', 'profile.html'));   
 });
});

app.post('/logout', (req, res) => {
    res.setHeader('X-XSS-Protection', '0');  // Désactiver la protection XSS
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Error during logout');
        }
        res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
    });
});

app.post('/register', (req, res) => {
    res.setHeader('X-XSS-Protection', '0');  // Désactiver la protection XSS
    const { username, password, email } = req.body;
    const query = `INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`; 
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send('Error registering user');
        }
        res.send('User registered!');
    });
});

app.get('/users', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        res.json(results);
    });
});

app.post('/update-profile', (req, res) => {
    res.setHeader('X-XSS-Protection', '0');  // Désactiver la protection XSS
    const { username, newPassword, email } = req.body;
    const query = `UPDATE users SET password = '${newPassword}', email = '${email}' WHERE username = '${username}'`;
    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).send('Error updating profile');
        }
        res.send('Profile updated!');
    });
});
// Route pour récupérer un utilisateur par ID
app.get('/user/:id', (req, res) => {
    const { id } = req.params;
    res.setHeader('X-XSS-Protection', '0');  // Désactiver la protection XSS

    const query = `SELECT * FROM users WHERE id = ?`;
    db.query(query, [id], (err, results) => {
        if (err) {
            return res.status(500).send('Error fetching user');
        }
        if (results.length > 0) {
            res.json(results[0]); // Retourne les informations du premier utilisateur trouvé
        } else {
            res.status(404).send('User not found');
        }
    });
});

app.listen(3000, () => console.log('Vulnerable app running on port 3000'));
