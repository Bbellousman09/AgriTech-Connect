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
    cookie: {   
        secure: process.env.NODE_ENV === 'production' // Use true in production  
    }  
}));  

// Serve static files  
app.use(express.static('styles'));  
app.use(express.static('scripts'));  

// Routes  
app.get('/', (req, res) => {  
    res.sendFile(__dirname + '/index.html');  
});  

app.get('/about', (req, res) => {  
    res.sendFile(__dirname + '/about.html'); // Adjust the path if it's in a different folder  
});

app.get('/contact', (req, res) => {  
    res.sendFile(__dirname + '/contact.html'); // Adjust the path if it's in a different folder  
});

app.get('/features', (req, res) => {  
    res.sendFile(__dirname + '/features.html'); // Adjust the path if it's in a different folder  
});

app.get('/resources', (req, res) => {  
    res.sendFile(__dirname + '/resources.html'); // Adjust the path if it's in a different folder  
});

app.get('/register', (req, res) => {  
    res.sendFile(__dirname + '/register.html'); // Ensure register.html is in the same directory as server.js  
}); 

app.get('/login', (req, res) => {  
    const message = req.query.message ? req.query.message : '';  
    res.sendFile(__dirname + '/login.html'); // Optionally pass the message to the login page  
});  

app.get('/profile', (req, res) => {  
    if (!req.session.userId) {  
        return res.redirect('/login'); // Redirect to login if not logged in  
    }  
    
    db.query('SELECT * FROM users WHERE id = ?', [req.session.userId], (error, results) => {  
        if (error) {  
            return res.status(500).send('Error fetching user data');  
        }  
        if (results.length === 0) {  
            return res.status(404).send('User not found');  
        }  
        const user = results[0];  
        res.send(`<h1>Welcome, ${user.username}</h1><p>Email: ${user.email}</p><a href="/logout">Logout</a>`);  
    });  
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
            return res.status(400).send('Invalid credentials'); // User not found  
        }  
        
        const user = results[0];  
        const passwordMatch = await bcrypt.compare(password, user.password);  
        
        if (passwordMatch) {  
            req.session.userId = user.id;   
            res.redirect('/profile');  
        } else {  
            res.status(400).send('Invalid credentials');   
        }  
    });  
});  

app.get('/logout', (req, res) => {  
    req.session.destroy((err) => {  
        if (err) {  
            return res.status(500).send('Could not log out user');  
        }  
        res.redirect('/login'); // Redirect to login after logout  
    });  
});  

// Start the server  
app.listen(PORT, () => {  
    console.log(`Server is running on http://localhost:${PORT}`);  
});