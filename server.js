const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const upload = multer({ dest: 'uploads/' });
const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key';

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/instaclone',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware para verificar JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token requerido' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

// Inicializar base de datos
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        bio TEXT,
        profile_picture VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        image_url VARCHAR(255) NOT NULL,
        caption TEXT,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT unique_user_post UNIQUE (user_id, created_at)
      );

      CREATE TABLE IF NOT EXISTS reels (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        video_url VARCHAR(255) NOT NULL,
        caption TEXT,
        text_overlay JSONB,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT unique_user_reel UNIQUE (user_id, created_at)
      );

      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        reel_id INTEGER REFERENCES reels(id),
        user_id INTEGER REFERENCES users(id),
        comment TEXT NOT NULL,
        parent_id INTEGER REFERENCES comments(id),
        created_at TIMESTAMP DEFAULT NOW()
      );

      -- Asegurar restricción única en profile_picture
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'unique_user_profile_picture'
        ) THEN
          ALTER TABLE users
          ADD CONSTRAINT unique_user_profile_picture UNIQUE (id);
        END IF;
      END $$;
    `);
    console.log('Base de datos inicializada');
  } catch (error) {
    console.error('Error al inicializar la base de datos:', error);
  }
}

initializeDatabase();

// Registro
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username',
      [username, email, password]
    );
    const token = jwt.sign({ username: result.rows[0].username }, SECRET_KEY);
    res.json({ token });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ message: error.detail || 'Error al registrarse' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1 AND password = $2',
      [email, password]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    const token = jwt.sign({ username: result.rows[0].username }, SECRET_KEY);
    res.json({ token });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
});

// Subir foto de perfil
app.post('/api/users/profile-picture', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No se proporcionó ninguna imagen' });
    }
    const imageUrl = `/uploads/${req.file.filename}`;
    const userId = (await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.user.username]
    )).rows[0].id;

    const result = await pool.query(
      `INSERT INTO users (id, profile_picture)
       VALUES ($1, $2)
       ON CONFLICT (id)
       DO UPDATE SET profile_picture = EXCLUDED.profile_picture
       RETURNING profile_picture`,
      [userId, imageUrl]
    );
    res.json({ imageUrl: result.rows[0].profile_picture });
  } catch (error) {
    console.error('Error al subir foto de perfil:', error);
    res.status(500).json({ message: error.detail || 'Error al subir la foto de perfil' });
  }
});

// Obtener foto de perfil
app.get('/api/users/:username/profile-picture', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT profile_picture FROM users WHERE username = $1',
      [req.params.username]
    );
    res.json({ imageUrl: result.rows[0]?.profile_picture || null });
  } catch (error) {
    console.error('Error al obtener foto de perfil:', error);
    res.status(500).json({ message: 'Error al obtener la foto de perfil' });
  }
});

// Actualizar bio
app.post('/api/users/bio', authenticateToken, async (req, res) => {
  const { bio } = req.body;
  try {
    await pool.query(
      'UPDATE users SET bio = $1 WHERE username = $2',
      [bio, req.user.username]
    );
    res.json({ message: 'Bio actualizada' });
  } catch (error) {
    console.error('Error al actualizar bio:', error);
    res.status(500).json({ message: 'Error al actualizar la bio' });
  }
});

// Obtener bio
app.get('/api/users/:username/bio', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT bio FROM users WHERE username = $1',
      [req.params.username]
    );
    res.json({ bio: result.rows[0]?.bio || '' });
  } catch (error) {
    console.error('Error al obtener bio:', error);
    res.status(500).json({ message: 'Error al obtener la bio' });
  }
});

// Crear publicación
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
  const { caption } = req.body;
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No se proporcionó ninguna imagen' });
    }
    const imageUrl = `/uploads/${req.file.filename}`;
    const userId = (await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.user.username]
    )).rows[0].id;

    await pool.query(
      `INSERT INTO posts (user_id, image_url, caption)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, created_at)
       DO NOTHING`,
      [userId, imageUrl, caption]
    );
    res.json({ message: 'Publicación creada' });
  } catch (error) {
    console.error('Error al crear publicación:', error);
    res.status(500).json({ message: error.detail || 'Error al crear publicación' });
  }
});

// Obtener publicaciones
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.username
      FROM posts p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener publicaciones:', error);
    res.status(500).json({ message: 'Error al obtener publicaciones' });
  }
});

// Crear reel
app.post('/api/reels', authenticateToken, upload.single('video'), async (req, res) => {
  const { caption, text_overlay } = req.body;
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No se proporcionó ningún video' });
    }
    const videoUrl = `/uploads/${req.file.filename}`;
    const userId = (await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.user.username]
    )).rows[0].id;

    await pool.query(
      `INSERT INTO reels (user_id, video_url, caption, text_overlay)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, created_at)
       DO NOTHING`,
      [userId, videoUrl, caption, text_overlay ? JSON.parse(text_overlay) : null]
    );
    res.json({ message: 'Reel creado' });
  } catch (error) {
    console.error('Error al crear reel:', error);
    res.status(500).json({ message: error.detail || 'Error al crear reel' });
  }
});

// Obtener reels
app.get('/api/reels', authenticateToken, async (req, res) => {
  const { page = 1, limit = 5, sort = 'random' } = req.query;
  try {
    const offset = (page - 1) * limit;
    const orderBy = sort === 'random' ? 'RANDOM()' : 'created_at DESC';
    const result = await pool.query(`
      SELECT r.*, u.username
      FROM reels r
      JOIN users u ON r.user_id = u.id
      ORDER BY ${orderBy}
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener reels:', error);
    res.status(500).json({ message: 'Error al obtener reels' });
  }
});

// Crear comentario
app.post('/api/reels/:reelId/comments', authenticateToken, async (req, res) => {
  const { comment } = req.body;
  const { reelId } = req.params;
  try {
    const userId = (await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.user.username]
    )).rows[0].id;

    const result = await pool.query(
      `INSERT INTO comments (reel_id, user_id, comment)
       VALUES ($1, $2, $3)
       RETURNING id, reel_id, user_id, comment, created_at`,
      [reelId, userId, comment]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al crear comentario:', error);
    res.status(500).json({ message: error.detail || 'Error al crear comentario' });
  }
});

// Responder a comentario
app.post('/api/reels/:reelId/comments/:commentId/reply', authenticateToken, async (req, res) => {
  const { reply } = req.body;
  const { reelId, commentId } = req.params;
  try {
    const userId = (await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.user.username]
    )).rows[0].id;

    const result = await pool.query(
      `INSERT INTO comments (reel_id, user_id, comment, parent_id)
       VALUES ($1, $2, $3, $4)
       RETURNING id, reel_id, user_id, comment, parent_id, created_at`,
      [reelId, userId, reply, commentId]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error al responder comentario:', error);
    res.status(500).json({ message: error.detail || 'Error al responder comentario' });
  }
});

// Obtener comentarios
app.get('/api/reels/:reelId/comments', authenticateToken, async (req, res) => {
  const { reelId } = req.params;
  try {
    const result = await pool.query(`
      SELECT c.*, u.username
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.reel_id = $1
      ORDER BY c.created_at DESC
    `, [reelId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener comentarios:', error);
    res.status(500).json({ message: 'Error al obtener comentarios' });
  }
});

// Seguir/deseguir usuario
app.post('/api/users/:username/follow', authenticateToken, async (req, res) => {
  const { username } = req.params;
  try {
    const followerId = (await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [req.user.username]
    )).rows[0].id;
    const followedId = (await pool.query(
      'SELECT id FROM users WHERE username = $1',
      [username]
    )).rows[0].id;

    const result = await pool.query(
      `INSERT INTO followers (follower_id, followed_id)
       VALUES ($1, $2)
       ON CONFLICT (follower_id, followed_id)
       DO DELETE
       RETURNING *`,
      [followerId, followedId]
    );
    res.json({ message: result.rowCount > 0 ? 'Seguido' : 'Dejado de seguir' });
  } catch (error) {
    console.error('Error al seguir/dejar de seguir:', error);
    res.status(500).json({ message: error.detail || 'Error al seguir/dejar de seguir' });
  }
});

// Obtener seguidores
app.get('/api/users/:username/followers', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT COUNT(*) AS followers, (
         SELECT COUNT(*) 
         FROM followers 
         WHERE follower_id = (SELECT id FROM users WHERE username = $1)
       ) AS following
       FROM followers 
       WHERE followed_id = (SELECT id FROM users WHERE username = $1)`,
      [req.params.username]
    );
    res.json({
      followers: parseInt(result.rows[0].followers),
      following: parseInt(result.rows[0].following)
    });
  } catch (error) {
    console.error('Error al obtener seguidores:', error);
    res.status(500).json({ message: 'Error al obtener seguidores' });
  }
});

// Buscar usuarios
app.get('/api/users/search', authenticateToken, async (req, res) => {
  const { query } = req.query;
  try {
    const result = await pool.query(
      'SELECT username FROM users WHERE username ILIKE $1 LIMIT 10',
      [`%${query}%`]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error al buscar usuarios:', error);
    res.status(500).json({ message: 'Error al buscar usuarios' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
