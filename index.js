import express from 'express'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import mongoose from 'mongoose'
import { registerValidation } from './validations/auth.js';
import { validationResult} from 'express-validator';
import UserModel from './models/User.js'
import checkAuth from './middleware/checkAuth.js';

import * as UserController from './controllers/UserController.js'

mongoose
    .connect('mongodb+srv://admin:4-!-4TXeaCrBLGM@cluster0.gnchq.mongodb.net/blog?retryWrites=true&w=majority')
    .then( ()=> console.log('DB ok'))
    .catch((err) => console.log('DB error', err))

const app = express();

app.use(express.json());

app.post('/auth/login', registerValidation, UserController.login)

app.post('/auth/register', registerValidation, UserController.register);

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