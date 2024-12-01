require('dotenv').config(); // Load environment variables from .env file  

const express = require('express');  
const mysql = require('mysql2');  
const session = require('express-session');  
const bodyParser = require('body-parser');  
const bcrypt = require('bcryptjs');  

const app = express();  
const PORT = process.env.PORT || 3000;  

// Create a connection to the MySQL database using environment variables  
const db = mysql.createConnection({  
    host: process.env.DB_HOST,  
    user: process.env.DB_USER,  
    password: process.env.DB_PASSWORD,  
    database: process.env.DB_NAME  
});  

db.connect((err) => {  
    if (err) {  
        console.error('Error connecting to the database:', err.stack);  
        return;  
    }  
    console.log('Connected to the database.');  
});  

// Middleware  
app.use(bodyParser.urlencoded({ extended: true }));  
app.use(session({  
    secret: process.env.SESSION_SECRET,  
    resave: false,  
    saveUninitialized: true,  
    cookie: { secure: process.env.NODE_ENV === 'production' }  
}));  

// Serve static files from the root directory  
app.use(express.static(__dirname));  

// Routes  
app.get('/', (req, res) => {  
    res.sendFile(__dirname + '/index.html');  
});  

app.get('/about', (req, res) => {  
    res.sendFile(__dirname + '/about.html');  
});  

app.get('/contact', (req, res) => {  
    res.sendFile(__dirname + '/contact.html');  
});  

app.get('/features', (req, res) => {  
    res.sendFile(__dirname + '/features.html');  
});  

app.get('/resources', (req, res) => {  
    res.sendFile(__dirname + '/resources.html');  
});  

app.get('/register', (req, res) => {  
    res.sendFile(__dirname + '/register.html');  
});   

app.get('/login', (req, res) => {  
    res.sendFile(__dirname + '/login.html');  
});  

app.get('/profile', (req, res) => {  
    if (!req.session.userId) {  
        return res.redirect('/login');  // Redirect to login if the user is not authenticated  
    }  
    res.sendFile(__dirname + '/profile.html');  // Serve the profile HTML page  
}); 

app.post('/register', async (req, res) => {  
    const { username, email, password } = req.body;  

    // Basic validation  
    if (!username || !email || !password) {  
        return res.status(400).send('All fields are required!');  
    }  

    const hashedPassword = await bcrypt.hash(password, 10);  

    db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (error, results) => {  
        if (error) {  
            return res.status(400).send('Error registering user: ' + error.message);  
        }  
        res.redirect('/login?message=Registration successful! Please log in.');  
    });  
});  

app.post('/login', (req, res) => {  
    const { username, password } = req.body;  

    // Validation  
    if (!username || !password) {  
        return res.status(400).send('Both fields are required!');  
    }  

    db.query('SELECT * FROM users WHERE username = ?', [username], async (error, results) => {  
        if (error) {  
            return res.status(400).send('Error fetching user: ' + error.message);  
        }  

        if (results.length === 0) {  
            return res.status(400).send('Invalid credentials');  
        }  

        const user = results[0];  
        const passwordMatch = await bcrypt.compare(password, user.password);  

        if (passwordMatch) {  
            req.session.userId = user.id;  // Store user ID in session  
            res.redirect('/profile');        // Redirect to profile page on successful login  
        } else {  
            res.status(400).send('Invalid credentials');   
        }  
    });  
});
app.get('/api/user', (req, res) => {  
    if (!req.session.userId) {  
        return res.status(401).json({ message: 'Unauthorized' });  
    }  

    db.query('SELECT username, email, createdAt, profilePicture FROM users WHERE id = ?', [req.session.userId], (error, results) => {  
        if (error) {  
            return res.status(500).json({ error: 'Database error' });  
        }  

        if (results.length === 0) {  
            return res.status(404).json({ message: 'User not found' });  
        }  

        const user = results[0];  
        res.json(user);  
    });  
});  

app.get('/logout', (req, res) => {  
    req.session.destroy((err) => {  
        if (err) {  
            return res.status(500).send('Could not log out user');  
        }  
        res.redirect('/login');  
    });  
});  

// Start the server  
app.listen(PORT, () => {  
    console.log(`Server is running on http://localhost:${PORT}`);  
});