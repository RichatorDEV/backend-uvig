const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Configuración de Multer para subir archivos
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.random().toString(36).substring(2, 15)}${ext}`);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'video/mp4'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de archivo no permitido. Usa JPEG, PNG o MP4.'), false);
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 } // Límite de 50MB
});

// Servir archivos estáticos con URL absoluta
app.use('/uploads', express.static(uploadDir));

// Middleware para manejar errores de Multer
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: `Error de Multer: ${err.message}` });
  } else if (err) {
    return res.status(400).json({ message: err.message });
  }
  next();
};
app.use(handleMulterError);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

const JWT_SECRET = process.env.JWT_SECRET || 'mi_secreto_super_seguro_123';

const initDatabase = async (retries = 3, delay = 2000) => {
  for (let i = 0; i < retries; i++) {
    try {
      console.log(`Intento ${i + 1} de conexión a la base de datos...`);
      const client = await pool.connect();
      console.log('Conexión a la base de datos establecida.');

      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          email VARCHAR(100) UNIQUE NOT NULL,
          password VARCHAR(100) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Tabla "users" creada o ya existe.');

      await client.query(`
        CREATE TABLE IF NOT EXISTS posts (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          caption TEXT NOT NULL,
          image_url VARCHAR(200) NOT NULL,
          likes INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Tabla "posts" creada o ya existe.');

      await client.query(`
        CREATE TABLE IF NOT EXISTS followers (
          id SERIAL PRIMARY KEY,
          follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          followed_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(follower_id, followed_id)
        );
      `);
      console.log('Tabla "followers" creada o ya existe.');

      await client.query(`
        CREATE TABLE IF NOT EXISTS profile_pictures (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          image_url VARCHAR(200) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Tabla "profile_pictures" creada o ya existe.');

      await client.query(`
        CREATE TABLE IF NOT EXISTS messages (
          id SERIAL PRIMARY KEY,
          sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          content TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Tabla "messages" creada o ya existe.');

      await client.query(`
        CREATE TABLE IF NOT EXISTS reels (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          video_url VARCHAR(200) NOT NULL,
          caption TEXT,
          text_overlay TEXT,
          music_url VARCHAR(200),
          likes INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Tabla "reels" creada o ya existe.');

      await client.query(`
        CREATE TABLE IF NOT EXISTS reel_comments (
          id SERIAL PRIMARY KEY,
          reel_id INTEGER REFERENCES reels(id) ON DELETE CASCADE,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          comment TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Tabla "reel_comments" creada o ya existe.');

      await client.release();
      console.log('Tablas creadas o verificadas correctamente.');
      return;
    } catch (error) {
      console.error(`Error en el intento ${i + 1}:`, error);
      if (i < retries - 1) {
        console.log(`Reintentando en ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  console.error('No se pudo conectar a la base de datos tras varios intentos.');
};

initDatabase();

// Middleware para verificar token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token requerido' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

// Registro
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username',
      [username, email, hashedPassword]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ token });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(400).json({ message: 'Error al registrarse, usuario o email ya existe' });
  }
});

// Inicio de sesión
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
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
      return res.status(400).json({ message: 'No se proporcionó imagen' });
    }
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    await pool.query(
      'INSERT INTO profile_pictures (user_id, image_url) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET image_url = $2',
      [req.user.id, imageUrl]
    );
    res.json({ imageUrl });
  } catch (error) {
    console.error('Error al subir foto de perfil:', error);
    res.status(500).json({ message: 'Error al subir foto de perfil' });
  }
});

// Obtener foto de perfil
app.get('/api/users/:username/profile-picture', authenticateToken, async (req, res) => {
  const { username } = req.params;
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (!userResult.rows[0]) return res.status(404).json({ message: 'Usuario no encontrado' });
    const userId = userResult.rows[0].id;
    const result = await pool.query('SELECT image_url FROM profile_pictures WHERE user_id = $1', [userId]);
    res.json({ imageUrl: result.rows[0]?.image_url || null });
  } catch (error) {
    console.error('Error al obtener foto de perfil:', error);
    res.status(500).json({ message: 'Error al obtener foto de perfil' });
  }
});

// Crear publicación
app.post('/api/posts', authenticateToken, async (req, res) => {
  const { caption, image_url } = req.body;
  try {
    await pool.query(
      'INSERT INTO posts (user_id, caption, image_url) VALUES ($1, $2, $3)',
      [req.user.id, caption, image_url]
    );
    res.status(201).json({ message: 'Publicación creada' });
  } catch (error) {
    console.error('Error al crear publicación:', error);
    res.status(500).json({ message: 'Error al crear publicación' });
  }
});

// Obtener publicaciones
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.id, p.caption, p.image_url, p.likes, p.created_at, u.username
      FROM posts p JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener publicaciones:', error);
    res.status(500).json({ message: 'Error al obtener publicaciones' });
  }
});

// Seguir/deseguir usuario
app.post('/api/users/:username/follow', authenticateToken, async (req, res) => {
  const { username } = req.params;
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (!userResult.rows[0]) return res.status(404).json({ message: 'Usuario no encontrado' });

    const followedId = userResult.rows[0].id;
    const followerId = req.user.id;

    if (followerId === followedId) {
      return res.status(400).json({ message: 'No puedes seguirte a ti mismo' });
    }

    const followResult = await pool.query(
      'SELECT * FROM followers WHERE follower_id = $1 AND followed_id = $2',
      [followerId, followedId]
    );

    if (followResult.rows.length > 0) {
      await pool.query(
        'DELETE FROM followers WHERE follower_id = $1 AND followed_id = $2',
        [followerId, followedId]
      );
      res.json({ message: 'Dejaste de seguir al usuario' });
    } else {
      await pool.query(
        'INSERT INTO followers (follower_id, followed_id) VALUES ($1, $2)',
        [followerId, followedId]
      );
      res.json({ message: 'Ahora sigues al usuario' });
    }
  } catch (error) {
    console.error('Error al seguir/deseguir:', error);
    res.status(500).json({ message: 'Error al seguir/deseguir' });
  }
});

// Obtener conteo de seguidores
app.get('/api/users/:username/followers', authenticateToken, async (req, res) => {
  const { username } = req.params;
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (!userResult.rows[0]) return res.status(404).json({ message: 'Usuario no encontrado' });
    const userId = userResult.rows[0].id;
    const followers = await pool.query('SELECT COUNT(*) FROM followers WHERE followed_id = $1', [userId]);
    const following = await pool.query('SELECT COUNT(*) FROM followers WHERE follower_id = $1', [userId]);
    res.json({
      followers: parseInt(followers.rows[0].count),
      following: parseInt(following.rows[0].count)
    });
  } catch (error) {
    console.error('Error al obtener conteo de seguidores:', error);
    res.status(500).json({ message: 'Error al obtener conteo' });
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

// Enviar mensaje
app.post('/api/messages', authenticateToken, async (req, res) => {
  const { receiver_username, content } = req.body;
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [receiver_username]);
    if (!userResult.rows[0]) return res.status(404).json({ message: 'Usuario no encontrado' });
    const receiverId = userResult.rows[0].id;
    await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, content) VALUES ($1, $2, $3)',
      [req.user.id, receiverId, content]
    );
    res.status(201).json({ message: 'Mensaje enviado' });
  } catch (error) {
    console.error('Error al enviar mensaje:', error);
    res.status(500).json({ message: 'Error al enviar mensaje' });
  }
});

// Obtener mensajes
app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT m.id, m.content, m.created_at, u1.username AS sender, u2.username AS receiver
      FROM messages m
      JOIN users u1 ON m.sender_id = u1.id
      JOIN users u2 ON m.receiver_id = u2.id
      WHERE m.sender_id = $1 OR m.receiver_id = $1
      ORDER BY m.created_at DESC
    `, [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener mensajes:', error);
    res.status(500).json({ message: 'Error al obtener mensajes' });
  }
});

// Subir reel
app.post('/api/reels', authenticateToken, upload.single('video'), async (req, res) => {
  const { caption, text_overlay, music_url } = req.body;
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No se proporcionó video' });
    }
    const videoUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    const result = await pool.query(
      'INSERT INTO reels (user_id, video_url, caption, text_overlay, music_url) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [req.user.id, videoUrl, caption, text_overlay, music_url]
    );
    res.status(201).json({ message: 'Reel creado', reelId: result.rows[0].id, videoUrl });
  } catch (error) {
    console.error('Error al crear reel:', error);
    res.status(500).json({ message: 'Error al crear reel' });
  }
});

// Obtener reels
app.get('/api/reels', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT r.id, r.video_url, r.caption, r.text_overlay, r.music_url, r.likes, r.created_at, u.username
      FROM reels r JOIN users u ON r.user_id = u.id
      ORDER BY r.created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener reels:', error);
    res.status(500).json({ message: 'Error al obtener reels' });
  }
});

// Comentar reel
app.post('/api/reels/:reelId/comments', authenticateToken, async (req, res) => {
  const { reelId } = req.params;
  const { comment } = req.body;
  try {
    await pool.query(
      'INSERT INTO reel_comments (reel_id, user_id, comment) VALUES ($1, $2, $3)',
      [reelId, req.user.id, comment]
    );
    res.status(201).json({ message: 'Comentario añadido' });
  } catch (error) {
    console.error('Error al comentar reel:', error);
    res.status(500).json({ message: 'Error al comentar reel' });
  }
});

// Obtener comentarios de un reel
app.get('/api/reels/:reelId/comments', authenticateToken, async (req, res) => {
  const { reelId } = req.params;
  try {
    const result = await pool.query(`
      SELECT rc.id, rc.comment, rc.created_at, u.username
      FROM reel_comments rc JOIN users u ON rc.user_id = u.id
      WHERE rc.reel_id = $1
      ORDER BY rc.created_at DESC
    `, [reelId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error al obtener comentarios:', error);
    res.status(500).json({ message: 'Error al obtener comentarios' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
