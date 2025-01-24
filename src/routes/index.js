const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('../models/User');

// Rota de teste
router.get('/', (req, res) => {
    res.send('Rota de teste');
});

router.get('/users/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // Verifica se o id do usuário no token corresponde ao id da rota
    if (req.userId !== id) {
        return res.status(403).json({ message: 'Acesso negado' });
    }

    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ message: 'Token não fornecido' });

    try {
        const secret = process.env.SECRET;
        const decoded = jwt.verify(token, secret);

        // Adiciona o id do usuário ao request para usar nas rotas
        req.userId = decoded.id;

        next();
    } catch (e) {
        return res.status(403).json({ message: 'Token inválido' });
    }
}

router.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;
    const existingUser = await User.findOne({ email });

    if (!name || !email || !password || !confirmPassword) {
        return res.status(422).json({ message: 'Preencha todos os campos' });
    }
    if (password !== confirmPassword) {
        return res.status(422).json({ message: 'As senhas devem ser iguais' });
    }
    if (existingUser) {
        return res.status(422).json({ message: 'Já existe um usuário com este email' });
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(200).json({ message: 'Usuário cadastrado com sucesso' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Falha ao registrar o usuário' });
    }
});

router.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(422).json({ message: 'Preencha todos os campos' });
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(404).json({ message: 'Usuário não encontrado' });
    }

    const checkPassword = await bcrypt.compare(password, user.password);

    if (!checkPassword) {
        return res.status(422).json({ message: 'Senha inválida' });
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret
        );

        res.status(200).json({ message: 'Login realizado com sucesso', token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Falha ao registrar o usuário' });
    }
});

module.exports = router;