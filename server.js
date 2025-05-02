const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Crear tablas automáticamente
const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        caption TEXT NOT NULL,
        image_url VARCHAR(200) NOT NULL,
        likes INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS followers (
        id SERIAL PRIMARY KEY,
        follower_id INTEGER REFERENCES users(id),
        followed_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(follower_id, followed_id)
      );
    `);
    console.log('Tablas creadas o verificadas correctamente');
  } catch (error) {
    console.error('Error al crear tablas:', error);
  }
};

// Inicializar base de datos al arrancar
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
    res.status(500).json({ message: 'Error al iniciar sesión' });
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
    res.status(500).json({ message: 'Error al seguir/deseguir' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));
