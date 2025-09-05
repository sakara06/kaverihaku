// server.js - Main Node.js server
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Vain kuvat on sallittuja!'), false);
        }
    }
});

// Initialize SQLite database
const db = new sqlite3.Database('./friendfinder.db');

// Create tables
db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        age INTEGER,
        bio TEXT,
        photo TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_active DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Matches table
    db.run(`CREATE TABLE IF NOT EXISTS matches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user1_id) REFERENCES users (id),
        FOREIGN KEY (user2_id) REFERENCES users (id),
        UNIQUE(user1_id, user2_id)
    )`);

    // Likes table (for tracking who liked whom)
    db.run(`CREATE TABLE IF NOT EXISTS likes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        liker_id INTEGER NOT NULL,
        liked_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (liker_id) REFERENCES users (id),
        FOREIGN KEY (liked_id) REFERENCES users (id),
        UNIQUE(liker_id, liked_id)
    )`);

    // Messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        match_id INTEGER NOT NULL,
        sender_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (match_id) REFERENCES matches (id),
        FOREIGN KEY (sender_id) REFERENCES users (id)
    )`);
});

// JWT middleware for authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes

// Auth Routes
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name, age } = req.body;

        if (!email || !password || !name || !age) {
            return res.status(400).json({ error: 'Kaikki kohdat vaaditaan' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (email, password, name, age) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, name, age],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'Sähköposti on jo käytössä' });
                    }
                    return res.status(500).json({ error: 'Tietokannan virhe' });
                }

                const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET);
                res.json({ 
                    token, 
                    user: { id: this.lastID, email, name, age }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Palvelin virhe' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Sähköposti ja salasana vaaditaan' });
        }

        db.get(
            'SELECT * FROM users WHERE email = ?',
            [email],
            async (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Tietokannan virhe' });
                }

                if (!user || !(await bcrypt.compare(password, user.password))) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                // Update last active
                db.run('UPDATE users SET last_active = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

                const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
                res.json({ 
                    token, 
                    user: { 
                        id: user.id, 
                        email: user.email, 
                        name: user.name, 
                        age: user.age,
                        bio: user.bio,
                        photo: user.photo
                    }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Palvelin virhe' });
    }
});

// Profile Routes
app.get('/api/profile', authenticateToken, (req, res) => {
    db.get(
        'SELECT id, email, name, age, bio, photo FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Tietokannan virhe' });
            }
            if (!user) {
                return res.status(404).json({ error: 'Käyttäjää ei löytynyt' });
            }
            res.json(user);
        }
    );
});

app.put('/api/profile', authenticateToken, upload.single('photo'), (req, res) => {
    const { name, age, bio } = req.body;
    let photoPath = null;

    if (req.file) {
        photoPath = req.file.filename;
    }

    let query = 'UPDATE users SET name = ?, age = ?, bio = ?';
    let params = [name, age, bio];

    if (photoPath) {
        query += ', photo = ?';
        params.push(photoPath);
    }

    query += ' WHERE id = ?';
    params.push(req.user.id);

    db.run(query, params, function(err) {
        if (err) {
            return res.status(500).json({ error: 'Tietokannan virhe' });
        }

        // Get updated user data
        db.get(
            'SELECT id, email, name, age, bio, photo FROM users WHERE id = ?',
            [req.user.id],
            (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Tietokannan virhe' });
                }
                res.json(user);
            }
        );
    });
});

// Discovery Routes
app.get('/api/discover', authenticateToken, (req, res) => {
    // Get users that haven't been liked/passed by current user
    const query = `
        SELECT u.id, u.name, u.age, u.bio, u.photo
        FROM users u
        WHERE u.id != ? 
        AND u.id NOT IN (
            SELECT liked_id FROM likes WHERE liker_id = ?
        )
        ORDER BY RANDOM()
        LIMIT 10
    `;

    db.all(query, [req.user.id, req.user.id], (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Tietokannan virhe' });
        }
        res.json(users);
    });
});

app.post('/api/like', authenticateToken, (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required' });
    }

    // Insert like
    db.run(
        'INSERT OR IGNORE INTO likes (liker_id, liked_id) VALUES (?, ?)',
        [req.user.id, userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Tietokannan virhe' });
            }

            // Check if it's a mutual like
            db.get(
                'SELECT id FROM likes WHERE liker_id = ? AND liked_id = ?',
                [userId, req.user.id],
                (err, mutualLike) => {
                    if (err) {
                        return res.status(500).json({ error: 'Tietokannan virhe' });
                    }

                    if (mutualLike) {
                        // Create match
                        const user1Id = Math.min(req.user.id, userId);
                        const user2Id = Math.max(req.user.id, userId);

                        db.run(
                            'INSERT OR IGNORE INTO matches (user1_id, user2_id) VALUES (?, ?)',
                            [user1Id, user2Id],
                            function(err) {
                                if (err) {
                                    return res.status(500).json({ error: 'Tietokannan virhe' });
                                }
                                res.json({ match: true, matchId: this.lastID });
                            }
                        );
                    } else {
                        res.json({ match: false });
                    }
                }
            );
        }
    );
});

app.post('/api/pass', authenticateToken, (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'Käyttäjä ID vaaditaan' });
    }

    // Insert a "pass" as a like with negative value or separate table
    // For simplicity, we'll just insert into likes table to mark as seen
    db.run(
        'INSERT OR IGNORE INTO likes (liker_id, liked_id) VALUES (?, ?)',
        [req.user.id, userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Tietokannan virhe' });
            }
            res.json({ success: true });
        }
    );
});

// Matches Routes
app.get('/api/matches', authenticateToken, (req, res) => {
    const query = `
        SELECT 
            m.id as match_id,
            m.created_at,
            u.id,
            u.name,
            u.age,
            u.photo,
            u.bio
        FROM matches m
        JOIN users u ON (
            CASE 
                WHEN m.user1_id = ? THEN u.id = m.user2_id
                ELSE u.id = m.user1_id
            END
        )
        WHERE m.user1_id = ? OR m.user2_id = ?
        ORDER BY m.created_at DESC
    `;

    db.all(query, [req.user.id, req.user.id, req.user.id], (err, matches) => {
        if (err) {
            return res.status(500).json({ error: 'Tietokannan virhe' });
        }
        res.json(matches);
    });
});

// Messages Routes
app.get('/api/messages/:matchId', authenticateToken, (req, res) => {
    const { matchId } = req.params;

    // First verify user is part of this match
    db.get(
        'SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
        [matchId, req.user.id, req.user.id],
        (err, match) => {
            if (err) {
                return res.status(500).json({ error: 'Tietokannan virhe' });
            }
            if (!match) {
                return res.status(403).json({ error: 'Pääsy kielletty' });
            }

            // Get messages
            const query = `
                SELECT 
                    m.id,
                    m.content,
                    m.created_at,
                    m.sender_id,
                    u.name as sender_name
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.match_id = ?
                ORDER BY m.created_at ASC
            `;

            db.all(query, [matchId], (err, messages) => {
                if (err) {
                    return res.status(500).json({ error: 'Tietokannan virhe' });
                }
                res.json(messages);
            });
        }
    );
});

app.post('/api/messages', authenticateToken, (req, res) => {
    const { matchId, content } = req.body;

    if (!matchId || !content) {
        return res.status(400).json({ error: 'Match ID ja sisältö vaaditaan' });
    }

    // Verify user is part of this match
    db.get(
        'SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
        [matchId, req.user.id, req.user.id],
        (err, match) => {
            if (err) {
                return res.status(500).json({ error: 'Tietokannan virhe' });
            }
            if (!match) {
                return res.status(403).json({ error: 'Pääsy kielletty' });
            }

            // Insert message
            db.run(
                'INSERT INTO messages (match_id, sender_id, content) VALUES (?, ?, ?)',
                [matchId, req.user.id, content],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Tietokannan virhe' });
                    }

                    const message = {
                        id: this.lastID,
                        match_id: matchId,
                        sender_id: req.user.id,
                        content,
                        created_at: new Date().toISOString()
                    };

                    // Emit to socket room
                    io.to(`match_${matchId}`).emit('new_message', message);

                    res.json(message);
                }
            );
        }
    );
});

// Socket.io for real-time chat
io.on('connection', (socket) => {
    console.log('Käyttäjä yhdistyi:', socket.id);

    socket.on('join_match', (matchId) => {
        socket.join(`match_${matchId}`);
        console.log(`Käyttäjä ${socket.id} liittyi matchiin ${matchId}`);
    });

    socket.on('leave_match', (matchId) => {
        socket.leave(`match_${matchId}`);
        console.log(`Käyttäjä ${socket.id} jätti matchin ${matchId}`);
    });

    socket.on('disconnect', () => {
        console.log('Käyttäjä lopetti:', socket.id);
    });
});

// Serve HTML pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/discover', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'discover.html'));
});

app.get('/matches', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'matches.html'));
});

app.get('/chat/:matchId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// Start server
server.listen(PORT, () => {
    console.log(`Kaverit sivusto on käynnissä portissa ${PORT}`);
});

// package.json
/*
{
  "name": "friendfinder",
  "version": "1.0.0",
  "description": "A social discovery web app",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "sqlite3": "^5.1.6",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "multer": "^1.4.5-lts.1",
    "socket.io": "^4.7.2"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
*/