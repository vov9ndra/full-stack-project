import express from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import { registerValidation } from './validations/auth.js';
import { validationResult} from 'express-validator';
import UserModel from './models/User.js'
import checkAuth from './middleware/checkAuth.js';

mongoose
    .connect('mongodb+srv://admin:4-!-4TXeaCrBLGM@cluster0.gnchq.mongodb.net/blog?retryWrites=true&w=majority')
    .then( ()=> console.log('DB ok'))
    .catch((err) => console.log('DB error', err))

const app = express();

app.use(express.json());

app.post('/auth/login', registerValidation, async (req, res) => {
    try {
        const user = await UserModel.findOne({ email: req.body.email})
        if (!user) {
             return res.status(400).json({
                 message: 'пользователь не найден'
             })
        };

        const isValidPassword = await bcrypt.compare(req.body.password, user._doc.passwordHash)

        if (!isValidPassword) {
            return res.status(400).json({
                message: 'невеный логин или пароль'
            })
        }

        const token = jwt.sign(
            {
                _id: user._id,
            },
            'secret123',
            {
                expiresIn: '30d'
            }
        );

        const { passwordHash, ...userData } = user._doc

        res.json({
            ...userData,
            token
        })
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: 'Не удалось авторизоваться'
        })
    }
})

app.post('/auth/register', registerValidation, async (req, res) => {
    try {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json(errors.array())
        }

        const password = req.body.password;
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt)

        const doc = new UserModel({
            email: req.body.email,
            passwordHash: hash,
            avatarUrl: req.body.avatarUrl,
            fullName: req.body.fullName
        });

        const user = await doc.save();

        const token = jwt.sign(
            {
                _id: user._id,
            },
            'secret123',
            {
                expiresIn: '30d'
            }
        );

        const { passwordHash, ...userData } = user._doc

        res.json({
            ...userData,
            token
        })
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: 'Не удалось зарегистрироваться'
        })
    }
});

app.get('/auth/me', checkAuth, async (req, res) => {
    try {
        const user = await UserModel.findById(req.userId)

        if (!user) {
          return res.status(404).json({
              message: 'пользователь не найден'
          })
        }

        const { passwordHash, ...userData } = user._doc
        res.json(userData)

    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: 'нет доступа'
        })
    }
})

app.listen(4444, (err) => {
    if (err) {
        return console.log(err);
    }

    console.log('Server OK')
})