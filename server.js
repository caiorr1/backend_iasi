const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors()); // Habilita CORS
app.use(express.json()); // Middleware para parsear JSON

const PORT = 3000;
const SECRET_KEY = 'seuSecretSuperSecreto'; // Substitua pela sua chave secreta real

const db = new sqlite3.Database('banco-de-dados.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados SQLite', err.message);
    } else {
        console.log('Conectado ao banco de dados SQLite.');
        db.run("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT)");
    }
});

// Middleware para verificar o token JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    if (!token) return res.status(401).send({ error: 'Acesso negado' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).send({ error: 'Token inválido' });
        }
        req.user = user;
        next();
    });
}

// Rota para registrar um novo usuário
app.post('/registro', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash da senha com bcrypt
        const sql = `INSERT INTO usuarios (email, password) VALUES (?, ?)`;
        db.run(sql, [email, hashedPassword], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: 'Usuário registrado com sucesso' });
        });
    } catch (error) {
        console.error('Erro ao registrar usuário:', error);
        res.status(500).json({ error: 'Erro ao registrar usuário' });
    }
});

// Rota para autenticar o usuário e gerar token JWT
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }
        const senhaValida = await bcrypt.compare(password, user.password);
        if (!senhaValida) {
            return res.status(401).json({ error: 'Senha incorreta' });
        }
        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' }); // Gera o token com validade de 1 hora
        res.json({ token });
    });
});

// Rota para listar todos os usuários
app.get('/usuarios', authenticateToken, (req, res) => {
    db.all("SELECT id, email FROM usuarios", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ usuarios: rows });
    });
});

// Rota para excluir um usuário específico
app.delete('/usuario/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run("DELETE FROM usuarios WHERE id = ?", id, function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado' });
        }
        res.json({ message: 'Usuário excluído com sucesso' });
    });
});

// Rota para atualizar um usuário específico
app.put('/usuario/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { email, password } = req.body;

    try {
        db.get("SELECT * FROM usuarios WHERE id = ?", [id], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (!user) {
                return res.status(404).json({ error: 'Usuário não encontrado' });
            }

            let updatedEmail = email || user.email;
            let updatedPassword = user.password;

            if (password) {
                updatedPassword = await bcrypt.hash(password, 10);
            }

            db.run("UPDATE usuarios SET email = ?, password = ? WHERE id = ?", [updatedEmail, updatedPassword, id], function(err) {
                if (err) {
                    return res.status(500).json({ error: err.message });
                }
                res.json({ message: 'Usuário atualizado com sucesso' });
            });
        });
    } catch (error) {
        console.error('Erro ao atualizar usuário:', error);
        res.status(500).json({ error: 'Erro ao atualizar usuário' });
    }
});

// Rota para redefinir a senha usando o email e a nova senha
app.post('/redefinir-senha', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        // Verifica se o usuário com o email fornecido existe
        db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao acessar o banco de dados.' });
            }
            if (!user) {
                return res.status(404).json({ error: 'Usuário não encontrado.' });
            }

            // Gera o hash da nova senha
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            // Atualiza a senha no banco de dados
            db.run("UPDATE usuarios SET password = ? WHERE email = ?", [hashedPassword, email], function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Erro ao atualizar a senha.' });
                }
                res.status(200).json({ message: 'Senha alterada com sucesso!' });
            });
        });
    } catch (error) {
        console.error('Erro ao redefinir senha:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});
