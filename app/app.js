const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const csrf = require('csurf');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Sécurisation des en-têtes HTTP
app.use(helmet());

// Protection CSRF
const csrfProtection = csrf();
app.use(csrfProtection);

// Gestion des sessions sécurisées
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: true, httpOnly: true, sameSite: 'strict' },
    })
);

app.use(express.static(path.join(__dirname, 'frontend')));

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    connectionLimit: 10,
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Route d'inscription sécurisée
app.post('/register',
    [
        body('username').isAlphanumeric().isLength({ min: 3, max: 20 }),
        body('email').isEmail(),
        body('password').isLength({ min: 8 }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email],
            (err, results) => {
                if (err) return res.status(500).send('Error registering user');
                res.send('User registered!');
            }
        );
    }
);

// Route de connexion sécurisée
app.post('/login',
    [
        body('email').isEmail(),
        body('password').notEmpty(),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { email, password } = req.body;

        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).send('Database error');

            if (results.length > 0) {
                const user = results[0];
                const passwordMatch = await bcrypt.compare(password, user.password);
                if (passwordMatch) {
                    req.session.user = user.id;
                    res.redirect(`/profile/${user.id}`);
                } else {
                    res.status(401).send('Invalid credentials');
                }
            } else {
                res.status(401).send('Invalid credentials');
            }
        });
    }
);

// Route de profil sécurisée
app.get('/profile/:id', (req, res) => {
    const { id } = req.params;

    if (!req.session.user || req.session.user != id) {
        return res.status(401).send('Unauthorized');
    }

    db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).send('Error fetching user data');
        if (results.length > 0) {
            res.sendFile(path.join(__dirname, 'frontend', 'profile.html'));
        } else {
            res.status(404).send('User not found');
        }
    });
});

// Route de mise à jour de profil sécurisée
app.post('/update-profile',
    [
        body('email').isEmail(),
        body('newPassword').isLength({ min: 8 }).optional(),
    ],
    async (req, res) => {
        if (!req.session.user) return res.status(401).send('Unauthorized');

        const { email, newPassword } = req.body;
        let query, params;

        if (newPassword) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            query = 'UPDATE users SET password = ?, email = ? WHERE id = ?';
            params = [hashedPassword, email, req.session.user];
        } else {
            query = 'UPDATE users SET email = ? WHERE id = ?';
            params = [email, req.session.user];
        }

        db.query(query, params, (err) => {
            if (err) return res.status(500).send('Error updating profile');
            res.send('Profile updated!');
        });
    }
);

// Route de récupération d'utilisateur sécurisée
app.get('/user/:id', (req, res) => {
    if (!req.session.user) return res.status(401).send('Unauthorized');

    const { id } = req.params;
    db.query('SELECT id, username, email FROM users WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).send('Error fetching user');
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).send('User not found');
        }
    });
});

// Route de déconnexion sécurisée
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send('Error during logout');
        res.redirect('/');
    });
});

app.listen(3000, () => console.log('Secure app running on port 3000'));
