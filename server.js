const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;
const SECRET_KEY = 'seuSecretSuperSecreto';

const db = new sqlite3.Database('banco-de-dados.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados SQLite', err.message);
    } else {
        console.log('Conectado ao banco de dados SQLite.');

        // Criação da tabela de usuários
        db.run("CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT)");

        // Criação da tabela de indústrias
        db.run(`CREATE TABLE IF NOT EXISTS industrias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            endereco TEXT NOT NULL,
            eficiencia_geral INTEGER,
            reducao_gastos INTEGER,
            reducao_pegada_carbono INTEGER,
            uso_energia_renovavel INTEGER,
            usuario_id INTEGER,
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
        )`);
    }
});

// Middleware para verificar o token JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
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
        const hashedPassword = await bcrypt.hash(password, 10);
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
        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
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
        db.get("SELECT * FROM usuarios WHERE email = ?", [email], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Erro ao acessar o banco de dados.' });
            }
            if (!user) {
                return res.status(404).json({ error: 'Usuário não encontrado.' });
            }

            const hashedPassword = await bcrypt.hash(newPassword, 10);

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

// Rota para adicionar uma nova indústria
app.post('/industrias', authenticateToken, (req, res) => {
    const { nome, endereco, eficiencia_geral, reducao_gastos, reducao_pegada_carbono, uso_energia_renovavel } = req.body;
    const usuario_id = req.user.id; // ID do usuário autenticado

    // Verifique se todos os campos estão preenchidos
    if (!nome || !endereco || !eficiencia_geral || !reducao_gastos || !reducao_pegada_carbono || !uso_energia_renovavel) {
        console.log('Campos faltando na requisição:', req.body);
        return res.status(400).json({ error: 'Por favor, preencha todos os campos.' });
    }

    const sql = `INSERT INTO industrias (nome, endereco, eficiencia_geral, reducao_gastos, reducao_pegada_carbono, uso_energia_renovavel, usuario_id) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;

    db.run(sql, [nome, endereco, eficiencia_geral, reducao_gastos, reducao_pegada_carbono, uso_energia_renovavel, usuario_id], function(err) {
        if (err) {
            console.error('Erro ao adicionar a indústria:', err.message);
            return res.status(500).json({ error: 'Erro ao adicionar a indústria.' });
        }
        console.log('Indústria adicionada com sucesso!', { industriaId: this.lastID });
        res.status(201).json({ message: 'Indústria adicionada com sucesso!', industriaId: this.lastID });
    });
});
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});

// Rota para listar todas as indústrias de um usuário autenticado
app.get('/industrias', authenticateToken, (req, res) => {
    const usuario_id = req.user.id; // ID do usuário autenticado

    const sql = `SELECT * FROM industrias WHERE usuario_id = ?`;

    db.all(sql, [usuario_id], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Erro ao acessar o banco de dados.' });
        }
        res.status(200).json({ industrias: rows });
    });
});

// Rota para editar uma indústria existente
app.put('/industrias/:id', authenticateToken, (req, res) => {
    const { id } = req.params; // ID da indústria a ser editada
    const { nome, endereco, eficiencia_geral, reducao_gastos, reducao_pegada_carbono, uso_energia_renovavel } = req.body;
    const usuario_id = req.user.id; // ID do usuário autenticado

    const sql = `
        UPDATE industrias 
        SET nome = ?, endereco = ?, eficiencia_geral = ?, reducao_gastos = ?, reducao_pegada_carbono = ?, uso_energia_renovavel = ?
        WHERE id = ? AND usuario_id = ?
    `;

    db.run(
        sql,
        [nome, endereco, eficiencia_geral, reducao_gastos, reducao_pegada_carbono, uso_energia_renovavel, id, usuario_id],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Erro ao editar a indústria.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Indústria não encontrada ou você não tem permissão para editá-la.' });
            }
            res.status(200).json({ message: 'Indústria editada com sucesso!' });
        }
    );
});