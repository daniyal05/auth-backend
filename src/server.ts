import express, { Request, Response } from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'; // <--- ЭТА СТРОКА ОБЯЗАТЕЛЬНА
import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';
// Загружаем переменные из .env файла
dotenv.config();

// Создаем клиент Prisma для работы с базой данных
const prisma = new PrismaClient();

// Создаем Express-приложение
const app = express();

// Middleware (промежуточные обработчики)
app.use(cors({
    origin: ['http://localhost:5173', 'https://auth-frontend-teal-three.vercel.app/'],
    credentials: true
}));
app.use(express.json()); // Учим сервер понимать JSON в запросах


// ENDPOINT: Регистрация нового пользователя

app.post('/api/register', async (req: Request, res:Response)=> {
    try {
        // 1. Получаем данные из тела запроса
        const {name, email, password} = req.body;
        // 2. Проверяем, что все поля заполнены
        if (!name || !email || !password){
            return res.status(400).json({ error: 'Все поля обязательны'});
        }


        // 3. Проверяем, существует ли уже пользователь с таким email
        const existingUser = await prisma.user.findUnique({
            where: {email}
        });

        if (existingUser){
            return res.status(400).json({error: 'Пользователь с таким email уже существует'});
        }
        // 4. Хешируем пароль (шифруем его)
            // 10 — это "сложность" хеширования (чем больше, тем безопаснее, но медленнее)
        const hashedPassword = await bcrypt.hash(password,10);


        // 5. Создаем нового пользователя в базе данных
        const newUser = await prisma.user.create({
            data: {
                name,               // пишем так потомучто в js такое можно сокращать вместо name : name
                email,              // email : email
                password: hashedPassword // Сохраняем зашифрованный пароль!
            }
        });

        // 6. Возвращаем успешный ответ
        res.status(201).json({
            message: 'Регистрация успешна',
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email
            }
        });


    } catch (error) {
        // Если что-то пошло не так — логируем ошибку и возвращаем 500
        console.error('Ошибка регистрации:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});


// ============================================
// ENDPOINT: Вход пользователя (Login)
// ============================================


app.post('/api/login', async (req:Request, res:Response) => {
    try {
        const{email, password} = req.body;

        // 1. Ищем пользователя по email
        const user = await prisma.user.findUnique({ where: { email } });

        // Если пользователя нет, сразу говорим "неверно", чтобы хакеры не могли угадывать email
        if (!user) {
            return res.status(400).json({error: 'Неверный email или пароль'})
        }

        // 2. Сравниваем введенный пароль с хешем из базы данных
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({error: 'Неверный email или пароль'});
        }

        // 3. Генерируем JWT токен (цифровой пропуск)
        // Мы кладем внутрь токена id и email, и подписываем его нашим секретным ключом
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET as string,
            { expiresIn: '7d' } // Токен будет действовать 7 дней
        );

        // 4. Отправляем токен и данные пользователя обратно
        res.json({
            message:'Вход успешен',
            token,
            user: {
                id : user.id,
                name: user.name,
                email:user.email
            }
        });
    } catch (error) {
        console.error('Ошибка входа:', error);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});



// ============================================
// Запуск сервера
// ============================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`✅ Сервер запущен на http://localhost:${PORT}`);
});