const express = require('express');
const path = require('path');
const cors = require('cors');
const mysql = require('mysql2/promise'); // Using mysql2 for promise support
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const ffmpeg = require('fluent-ffmpeg');

// Initialize express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MySQL Connection Pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '0799375874', // Change this to your MySQL password
    database: 'streamvibe',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Database initialization
async function initializeDatabase() {
    try {
        const connection = await pool.getConnection();
        
        // Create tables if they don't exist
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                email VARCHAR(100) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                profilePic VARCHAR(255) DEFAULT 'default-avatar.jpg',
                subscriptionPlan ENUM('free', 'premium', 'ultimate') DEFAULT 'free',
                subscriptionStartDate DATETIME,
                subscriptionEndDate DATETIME,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS videos (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                type ENUM('movie', 'series') NOT NULL,
                releaseYear INT,
                thumbnailUrl VARCHAR(255) NOT NULL,
                videoUrl VARCHAR(255) NOT NULL,
                duration INT,
                views INT DEFAULT 0,
                rating FLOAT DEFAULT 0,
                season INT,
                episode INT,
                episodeTitle VARCHAR(255),
                isPremium BOOLEAN DEFAULT FALSE,
                featured BOOLEAN DEFAULT FALSE,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS video_genres (
                id INT AUTO_INCREMENT PRIMARY KEY,
                videoId INT NOT NULL,
                genre VARCHAR(50) NOT NULL,
                FOREIGN KEY (videoId) REFERENCES videos(id) ON DELETE CASCADE
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS watch_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                videoId INT NOT NULL,
                progress FLOAT DEFAULT 0,
                lastWatched DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (videoId) REFERENCES videos(id) ON DELETE CASCADE,
                UNIQUE KEY user_video (userId, videoId)
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS watchlist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                videoId INT NOT NULL,
                addedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (videoId) REFERENCES videos(id) ON DELETE CASCADE,
                UNIQUE KEY user_video (userId, videoId)
            )
        `);
        
        await connection.query(`
            CREATE TABLE IF NOT EXISTS reviews (
                id INT AUTO_INCREMENT PRIMARY KEY,
                userId INT NOT NULL,
                videoId INT NOT NULL,
                rating INT NOT NULL,
                comment TEXT,
                createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (videoId) REFERENCES videos(id) ON DELETE CASCADE,
                UNIQUE KEY user_video_review (userId, videoId)
            )
        `);
        
        connection.release();
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

// Call the initialization function
initializeDatabase();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
    
    jwt.verify(token, 'your_jwt_secret', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token.' });
        req.user = user;
        next();
    });
};

// Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = file.mimetype.startsWith('image') ? 'public/images' : 'public/videos';
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 500000000 }, // 500MB limit
    fileFilter: (req, file, cb) => {
        const allowedMimeTypes = [
            'image/jpeg', 'image/png', 'image/gif',
            'video/mp4', 'video/mpeg', 'video/quicktime'
        ];
        if (allowedMimeTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type.'), false);
        }
    }
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user already exists
        const [existingUsers] = await pool.query(
            'SELECT * FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        
        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'User already exists' });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create new user
        const [result] = await pool.query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );
        
        // Generate JWT
        const token = jwt.sign(
            { id: result.insertId, username },
            'your_jwt_secret',
            { expiresIn: '1d' }
        );
        
        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: result.insertId,
                username,
                email,
                subscription: {
                    plan: 'free'
                },
                profilePic: 'default-avatar.jpg'
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const [users] = await pool.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );
        
        if (users.length === 0) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }
        
        const user = users[0];
        
        // Validate password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid username or password' });
        }
        
        // Generate JWT
        const token = jwt.sign(
            { id: user.id, username: user.username },
            'your_jwt_secret',
            { expiresIn: '1d' }
        );
        
        res.status(200).json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                subscription: {
                    plan: user.subscriptionPlan,
                    startDate: user.subscriptionStartDate,
                    endDate: user.subscriptionEndDate
                },
                profilePic: user.profilePic
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// User Routes
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT id, username, email, profilePic, subscriptionPlan, subscriptionStartDate, subscriptionEndDate, createdAt FROM users WHERE id = ?',
            [req.user.id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const user = users[0];
        
        res.status(200).json({
            id: user.id,
            username: user.username,
            email: user.email,
            profilePic: user.profilePic,
            subscription: {
                plan: user.subscriptionPlan,
                startDate: user.subscriptionStartDate,
                endDate: user.subscriptionEndDate
            },
            createdAt: user.createdAt
        });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/users/profile', authenticateToken, upload.single('profilePic'), async (req, res) => {
    try {
        const { username, email } = req.body;
        let profilePic = undefined;
        
        if (req.file) {
            profilePic = req.file.filename;
        }
        
        // Update profile data
        if (profilePic) {
            await pool.query(
                'UPDATE users SET username = ?, email = ?, profilePic = ? WHERE id = ?',
                [username, email, profilePic, req.user.id]
            );
        } else {
            await pool.query(
                'UPDATE users SET username = ?, email = ? WHERE id = ?',
                [username, email, req.user.id]
            );
        }
        
        // Get updated user data
        const [users] = await pool.query(
            'SELECT id, username, email, profilePic, subscriptionPlan, subscriptionStartDate, subscriptionEndDate FROM users WHERE id = ?',
            [req.user.id]
        );
        
        const user = users[0];
        
        res.status(200).json({
            message: 'Profile updated successfully',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                profilePic: user.profilePic,
                subscription: {
                    plan: user.subscriptionPlan,
                    startDate: user.subscriptionStartDate,
                    endDate: user.subscriptionEndDate
                }
            }
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/users/subscription', authenticateToken, async (req, res) => {
    try {
        const { plan } = req.body;
        
        if (!['free', 'premium', 'ultimate'].includes(plan)) {
            return res.status(400).json({ message: 'Invalid subscription plan' });
        }
        
        const startDate = new Date();
        const endDate = new Date();
        endDate.setMonth(endDate.getMonth() + 1); // 1 month subscription
        
        await pool.query(
            'UPDATE users SET subscriptionPlan = ?, subscriptionStartDate = ?, subscriptionEndDate = ? WHERE id = ?',
            [plan, startDate, endDate, req.user.id]
        );
        
        const [users] = await pool.query(
            'SELECT id, username, email, profilePic, subscriptionPlan, subscriptionStartDate, subscriptionEndDate FROM users WHERE id = ?',
            [req.user.id]
        );
        
        const user = users[0];
        
        res.status(200).json({
            message: 'Subscription updated successfully',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                profilePic: user.profilePic,
                subscription: {
                    plan: user.subscriptionPlan,
                    startDate: user.subscriptionStartDate,
                    endDate: user.subscriptionEndDate
                }
            }
        });
    } catch (error) {
        console.error('Subscription error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Video Routes
app.get('/api/videos', async (req, res) => {
    try {
        const { category, genre, search, limit = 10, page = 1 } = req.query;
        const offset = (parseInt(page) - 1) * parseInt(limit);
        
        let query = `
            SELECT v.*, 
            (SELECT GROUP_CONCAT(genre) FROM video_genres WHERE videoId = v.id) AS genres
            FROM videos v
            WHERE 1=1
        `;
        
        const queryParams = [];
        
        if (category === 'featured') {
            query += ' AND v.featured = TRUE';
        } else if (category === 'movies') {
            query += ' AND v.type = ?';
            queryParams.push('movie');
        } else if (category === 'series') {
            query += ' AND v.type = ?';
            queryParams.push('series');
        }
        
        if (genre) {
            query += ' AND v.id IN (SELECT videoId FROM video_genres WHERE genre = ?)';
            queryParams.push(genre);
        }
        
        if (search) {
            query += ' AND v.title LIKE ?';
            queryParams.push(`%${search}%`);
        }
        
        query += ' ORDER BY v.createdAt DESC LIMIT ? OFFSET ?';
        queryParams.push(parseInt(limit), offset);
        
        const [videos] = await pool.query(query, queryParams);
        
        // Convert genres string to array for each video
        videos.forEach(video => {
            if (video.genres) {
                video.genre = video.genres.split(',');
            } else {
                video.genre = [];
            }
            delete video.genres;
        });
        
        // Count total videos for pagination
        let countQuery = `
            SELECT COUNT(*) as total
            FROM videos v
            WHERE 1=1
        `;
        
        const countParams = [...queryParams.slice(0, -2)]; // Remove limit and offset params
        
        if (category === 'featured') {
            countQuery += ' AND v.featured = TRUE';
        } else if (category === 'movies') {
            countQuery += ' AND v.type = ?';
        } else if (category === 'series') {
            countQuery += ' AND v.type = ?';
        }
        
        if (genre) {
            countQuery += ' AND v.id IN (SELECT videoId FROM video_genres WHERE genre = ?)';
        }
        
        if (search) {
            countQuery += ' AND v.title LIKE ?';
        }
        
        const [totalResults] = await pool.query(countQuery, countParams);
        const total = totalResults[0].total;
        
        res.status(200).json({
            videos,
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(total / parseInt(limit))
            }
        });
    } catch (error) {
        console.error('Videos fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/videos/:id', async (req, res) => {
    try {
        // Increment views
        await pool.query('UPDATE videos SET views = views + 1 WHERE id = ?', [req.params.id]);
        
        // Get video data
        const [videos] = await pool.query(`
            SELECT v.*, 
            (SELECT GROUP_CONCAT(genre) FROM video_genres WHERE videoId = v.id) AS genres
            FROM videos v
            WHERE v.id = ?
        `, [req.params.id]);
        
        if (videos.length === 0) {
            return res.status(404).json({ message: 'Video not found' });
        }
        
        const video = videos[0];
        
        // Convert genres string to array
        if (video.genres) {
            video.genre = video.genres.split(',');
        } else {
            video.genre = [];
        }
        delete video.genres;
        
        // Create seriesInfo object if it's a series
        if (video.type === 'series') {
            video.seriesInfo = {
                season: video.season,
                episode: video.episode,
                episodeTitle: video.episodeTitle
            };
        }
        
        // Remove individual fields that are now in seriesInfo
        delete video.season;
        delete video.episode;
        delete video.episodeTitle;
        
        res.status(200).json(video);
    } catch (error) {
        console.error('Video fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/videos/watch-progress', authenticateToken, async (req, res) => {
    try {
        const { videoId, progress } = req.body;
        
        // Check if an entry already exists
        const [existing] = await pool.query(
            'SELECT * FROM watch_history WHERE userId = ? AND videoId = ?',
            [req.user.id, videoId]
        );
        
        if (existing.length > 0) {
            // Update existing entry
            await pool.query(
                'UPDATE watch_history SET progress = ?, lastWatched = NOW() WHERE userId = ? AND videoId = ?',
                [progress, req.user.id, videoId]
            );
        } else {
            // Create new entry
            await pool.query(
                'INSERT INTO watch_history (userId, videoId, progress) VALUES (?, ?, ?)',
                [req.user.id, videoId, progress]
            );
        }
        
        res.status(200).json({ message: 'Watch progress updated' });
    } catch (error) {
        console.error('Watch progress error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Watchlist Routes
app.get('/api/users/watchlist', authenticateToken, async (req, res) => {
    try {
        const [watchlist] = await pool.query(`
            SELECT v.*, 
            (SELECT GROUP_CONCAT(genre) FROM video_genres WHERE videoId = v.id) AS genres
            FROM videos v
            JOIN watchlist w ON v.id = w.videoId
            WHERE w.userId = ?
            ORDER BY w.addedAt DESC
        `, [req.user.id]);
        
        // Process each video to format genre and seriesInfo
        watchlist.forEach(video => {
            if (video.genres) {
                video.genre = video.genres.split(',');
            } else {
                video.genre = [];
            }
            delete video.genres;
            
            if (video.type === 'series') {
                video.seriesInfo = {
                    season: video.season,
                    episode: video.episode,
                    episodeTitle: video.episodeTitle
                };
            }
            
            delete video.season;
            delete video.episode;
            delete video.episodeTitle;
        });
        
        res.status(200).json(watchlist);
    } catch (error) {
        console.error('Watchlist fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/users/watchlist', authenticateToken, async (req, res) => {
    try {
        const { videoId } = req.body;
        
        // Check if video exists
        const [videos] = await pool.query('SELECT id FROM videos WHERE id = ?', [videoId]);
        if (videos.length === 0) {
            return res.status(404).json({ message: 'Video not found' });
        }
        
        // Check if already in watchlist
        const [existing] = await pool.query(
            'SELECT id FROM watchlist WHERE userId = ? AND videoId = ?',
            [req.user.id, videoId]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({ message: 'Video already in watchlist' });
        }
        
        // Add to watchlist
        await pool.query(
            'INSERT INTO watchlist (userId, videoId) VALUES (?, ?)',
            [req.user.id, videoId]
        );
        
        res.status(200).json({ message: 'Added to watchlist' });
    } catch (error) {
        console.error('Watchlist add error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/users/watchlist/:videoId', authenticateToken, async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM watchlist WHERE userId = ? AND videoId = ?',
            [req.user.id, req.params.videoId]
        );
        
        res.status(200).json({ message: 'Removed from watchlist' });
    } catch (error) {
        console.error('Watchlist remove error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reviews Routes
app.get('/api/videos/:id/reviews', async (req, res) => {
    try {
        const [reviews] = await pool.query(`
            SELECT r.*, u.username, u.profilePic
            FROM reviews r
            JOIN users u ON r.userId = u.id
            WHERE r.videoId = ?
            ORDER BY r.createdAt DESC
        `, [req.params.id]);
        
        // Format response to match expected structure
        const formattedReviews = reviews.map(review => ({
            ...review,
            userId: {
                _id: review.userId,
                username: review.username,
                profilePic: review.profilePic
            }
        }));
        
        // Remove redundant properties
        formattedReviews.forEach(review => {
            delete review.username;
            delete review.profilePic;
        });
        
        res.status(200).json(formattedReviews);
    } catch (error) {
        console.error('Reviews fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/videos/:id/reviews', authenticateToken, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        
        // Check if user already reviewed this video
        const [existingReviews] = await pool.query(
            'SELECT id FROM reviews WHERE userId = ? AND videoId = ?',
            [req.user.id, req.params.id]
        );
        
        if (existingReviews.length > 0) {
            return res.status(400).json({ message: 'You already reviewed this video' });
        }
        
        // Add review
        const [result] = await pool.query(
            'INSERT INTO reviews (userId, videoId, rating, comment) VALUES (?, ?, ?, ?)',
            [req.user.id, req.params.id, rating, comment]
        );
        
        // Update video rating
        const [reviews] = await pool.query(
            'SELECT rating FROM reviews WHERE videoId = ?',
            [req.params.id]
        );
        
        const totalRating = reviews.reduce((sum, review) => sum + review.rating, 0);
        const averageRating = totalRating / reviews.length;
        
        await pool.query(
            'UPDATE videos SET rating = ? WHERE id = ?',
            [averageRating, req.params.id]
        );
        
        // Get user info for response
        const [users] = await pool.query(
            'SELECT username, profilePic FROM users WHERE id = ?',
            [req.user.id]
        );
        
        const review = {
            id: result.insertId,
            userId: {
                _id: req.user.id,
                username: users[0].username,
                profilePic: users[0].profilePic
            },
            videoId: req.params.id,
            rating,
            comment,
            createdAt: new Date()
        };
        
        res.status(201).json(review);
    } catch (error) {
        console.error('Review submit error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin Routes for Content Management
app.post('/api/admin/videos', authenticateToken, upload.fields([
    { name: 'videoFile', maxCount: 1 },
    { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
    try {
        // Check admin permission (in a real app, add admin role column to users table)
        const [users] = await pool.query(
            'SELECT * FROM users WHERE id = ?',
            [req.user.id]
        );
        
        if (users.length === 0 || users[0].role !== 'admin') {
            return res.status(403).json({ message: 'Permission denied' });
        }
        
        const {
            title,
            description,
            type,
            genre,
            releaseYear,
            duration,
            isPremium,
            featured
        } = req.body;
        
        if (!req.files.videoFile || !req.files.thumbnail) {
            return res.status(400).json({ message: 'Video file and thumbnail are required' });
        }
        
        const videoUrl = req.files.videoFile[0].filename;
        const thumbnailUrl = req.files.thumbnail[0].filename;
        
        let season = null;
        let episode = null;
        let episodeTitle = null;
        
        if (type === 'series') {
            season = req.body.season;
            episode = req.body.episode;
            episodeTitle = req.body.episodeTitle;
        }
        
        // Insert video
        const [result] = await pool.query(
            `INSERT INTO videos (
                title, description, type, releaseYear, thumbnailUrl, videoUrl, 
                duration, isPremium, featured, season, episode, episodeTitle
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                title, description, type, releaseYear, thumbnailUrl, videoUrl,
                duration, isPremium === 'true', featured === 'true', season, episode, episodeTitle
            ]
        );
        
        const videoId = result.insertId;
        
        // Add genres
        if (genre) {
            const genres = genre.split(',');
            for (const genreItem of genres) {
                await pool.query(
                    'INSERT INTO video_genres (videoId, genre) VALUES (?, ?)',
                    [videoId, genreItem.trim()]
                );
            }
        }
        
        // Get complete video data for response
        const [videos] = await pool.query(`
            SELECT v.*, 
            (SELECT GROUP_CONCAT(genre) FROM video_genres WHERE videoId = v.id) AS genres
            FROM videos v
            WHERE v.id = ?
        `, [videoId]);
        
        const video = videos[0];
        
        // Format response
        if (video.genres) {
            video.genre = video.genres.split(',');
        } else {
            video.genre = [];
        }
        delete video.genres;
        
        if (video.type === 'series') {
            video.seriesInfo = {
                season: video.season,
                episode: video.episode,
                episodeTitle: video.episodeTitle
            };
        }
        
        delete video.season;
        delete video.episode;
        delete video.episodeTitle;
        
        res.status(201).json({
            message: 'Video uploaded successfully',
            video
        });
    } catch (error) {
        console.error('Video upload error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});