import { validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import UserModel from '../models/User.js';
import jwt from 'jsonwebtoken';
import checkAuth from '../middleware/checkAuth.js';


export const register = async (req, res) => {
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
};

export const login = async (req, res) => {
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
};
