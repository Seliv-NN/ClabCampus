// server.js
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const PORT = process.env.PORT || 3000;

// Настройка базы данных
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
    } else {
        console.log('Подключено к SQLite базе данных');
        initializeDatabase();
    }
});

// Инициализация базы данных
function initializeDatabase() {
    db.serialize(() => {
        // Создание таблицы пользователей
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            first_name TEXT,
            last_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);

        // Создание таблицы курсов
        db.run(`CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            level TEXT NOT NULL,
            teacher_id INTEGER,
            max_students INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (teacher_id) REFERENCES users(id)
        )`);

        // Создание таблицы расписания
        db.run(`CREATE TABLE IF NOT EXISTS schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            FOREIGN KEY (course_id) REFERENCES courses(id)
        )`);

        // Создание таблицы записей на курсы
        db.run(`CREATE TABLE IF NOT EXISTS enrollments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (course_id) REFERENCES courses(id),
            UNIQUE(user_id, course_id)
        )`);

        // Добавление тестовых данных, если база пуста
        db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
            if (row.count === 0) {
                const saltRounds = 10;
                const password = 'admin123';
                bcrypt.hash(password, saltRounds, (err, hash) => {
                    db.run(`INSERT INTO users (username, email, password, role, first_name, last_name) 
                           VALUES (?, ?, ?, ?, ?, ?)`, 
                           ['admin', 'admin@example.com', hash, 'teacher', 'Admin', 'User']);
                });

                db.run(`INSERT INTO courses (name, description, category, level, teacher_id, max_students)
                        VALUES (?, ?, ?, ?, ?, ?)`,
                        ['Программирование на Python', 'Основы программирования на Python для начинающих', 'Программирование', 'beginner', 1, 20]);

                db.run(`INSERT INTO schedule (course_id, day, start_time, end_time)
                        VALUES (?, ?, ?, ?)`,
                        [1, 'Понедельник', '14:00', '15:30']);
                db.run(`INSERT INTO schedule (course_id, day, start_time, end_time)
                        VALUES (?, ?, ?, ?)`,
                        [1, 'Среда', '14:00', '15:30']);
            }
        });
    });
}

// Настройка сессий
app.use(session({
    store: new SQLiteStore({
        db: 'sessions.db',
        dir: './'
    }),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 1 неделя
}));

// Middleware для проверки аутентификации
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    next();
}

// Middleware для проверки роли учителя
function requireTeacher(req, res, next) {
    if (req.session.role !== 'teacher') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    next();
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// API endpoints

// Регистрация пользователя
app.post('/api/register', (req, res) => {
    const { username, email, password, firstName, lastName } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        db.run(`INSERT INTO users (username, email, password, first_name, last_name) 
                VALUES (?, ?, ?, ?, ?)`, 
                [username, email, hash, firstName, lastName], 
                function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Пользователь с таким email или username уже существует' });
                }
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json({ success: true, userId: this.lastID });
        });
    });
});

// Авторизация пользователя
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
    }

    db.get(`SELECT id, username, password, role FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }

        bcrypt.compare(password, user.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ error: 'Неверные учетные данные' });
            }

            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;

            res.json({ 
                success: true, 
                user: { 
                    id: user.id, 
                    username: user.username, 
                    role: user.role 
                } 
            });
        });
    });
});

// Выход из системы
app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

// Получение информации о текущем пользователе
app.get('/api/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Не авторизован' });
    }

    db.get(`SELECT id, username, email, role, first_name, last_name FROM users WHERE id = ?`, 
           [req.session.userId], (err, user) => {
        if (err || !user) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(user);
    });
});

// Получение списка курсов
app.get('/api/courses', (req, res) => {
    const { category, level } = req.query;
    let query = `SELECT c.*, u.first_name || ' ' || u.last_name as teacher_name 
                 FROM courses c LEFT JOIN users u ON c.teacher_id = u.id`;
    const params = [];

    if (category || level) {
        query += ' WHERE ';
        const conditions = [];
        if (category) {
            conditions.push('c.category = ?');
            params.push(category);
        }
        if (level) {
            conditions.push('c.level = ?');
            params.push(level);
        }
        query += conditions.join(' AND ');
    }

    db.all(query, params, (err, courses) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }

        // Получаем расписание для каждого курса
        if (courses.length === 0) {
            return res.json([]);
        }

        const courseIds = courses.map(c => c.id);
        db.all(`SELECT course_id, day, start_time, end_time FROM schedule 
                WHERE course_id IN (${courseIds.map(() => '?').join(',')})`, 
                courseIds, (err, schedules) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            const scheduleMap = schedules.reduce((acc, s) => {
                if (!acc[s.course_id]) acc[s.course_id] = [];
                acc[s.course_id].push(s);
                return acc;
            }, {});

            const result = courses.map(course => ({
                ...course,
                schedule: scheduleMap[course.id] || []
            }));

            res.json(result);
        });
    });
});

// Получение деталей курса
app.get('/api/courses/:id', (req, res) => {
    const courseId = req.params.id;

    db.get(`SELECT c.*, u.first_name || ' ' || u.last_name as teacher_name 
            FROM courses c LEFT JOIN users u ON c.teacher_id = u.id 
            WHERE c.id = ?`, [courseId], (err, course) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        if (!course) {
            return res.status(404).json({ error: 'Курс не найден' });
        }

        db.all(`SELECT day, start_time, end_time FROM schedule WHERE course_id = ?`, 
               [courseId], (err, schedule) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            // Проверяем, записан ли пользователь на курс
            let isEnrolled = false;
            if (req.session.userId) {
                db.get(`SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?`, 
                       [req.session.userId, courseId], (err, row) => {
                    if (err) {
                        return res.status(500).json({ error: 'Ошибка сервера' });
                    }
                    isEnrolled = !!row;
                    
                    res.json({
                        ...course,
                        schedule,
                        isEnrolled,
                        canEnroll: !isEnrolled && req.session.userId
                    });
                });
            } else {
                res.json({
                    ...course,
                    schedule,
                    isEnrolled,
                    canEnroll: false
                });
            }
        });
    });
});

// Запись на курс
app.post('/api/courses/:id/enroll', requireAuth, (req, res) => {
    const courseId = req.params.id;
    const userId = req.session.userId;

    // Проверяем, есть ли место на курсе
    db.get(`SELECT max_students, 
            (SELECT COUNT(*) FROM enrollments WHERE course_id = ?) as enrolled_count
            FROM courses WHERE id = ?`, [courseId, courseId], (err, data) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        if (!data) {
            return res.status(404).json({ error: 'Курс не найден' });
        }
        if (data.enrolled_count >= data.max_students) {
            return res.status(400).json({ error: 'На курс нет свободных мест' });
        }

        // Проверяем, не записан ли уже пользователь
        db.get(`SELECT 1 FROM enrollments WHERE user_id = ? AND course_id = ?`, 
               [userId, courseId], (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            if (row) {
                return res.status(400).json({ error: 'Вы уже записаны на этот курс' });
            }

            // Записываем на курс
            db.run(`INSERT INTO enrollments (user_id, course_id) VALUES (?, ?)`, 
                   [userId, courseId], function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
                res.json({ success: true });
            });
        });
    });
});

// Получение расписания пользователя
app.get('/api/my-schedule', requireAuth, (req, res) => {
    const userId = req.session.userId;

    db.all(`SELECT c.id as course_id, c.name as course_name, 
                   s.day, s.start_time, s.end_time
            FROM enrollments e
            JOIN courses c ON e.course_id = c.id
            JOIN schedule s ON c.id = s.course_id
            WHERE e.user_id = ?
            ORDER BY s.day, s.start_time`, [userId], (err, schedule) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(schedule);
    });
});

// Получение списка преподавателей
app.get('/api/teachers', (req, res) => {
    db.all(`SELECT id, first_name, last_name, email FROM users WHERE role = 'teacher'`, 
           (err, teachers) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(teachers);
    });
});

// Добавление нового курса (для преподавателей)
app.post('/api/courses', requireAuth, requireTeacher, (req, res) => {
    const { name, description, category, level, max_students, schedule } = req.body;
    const teacherId = req.session.userId;

    if (!name || !category || !level || !max_students || !schedule || schedule.length === 0) {
        return res.status(400).json({ error: 'Не все обязательные поля заполнены' });
    }

    db.serialize(() => {
        db.run(`INSERT INTO courses (name, description, category, level, teacher_id, max_students)
                VALUES (?, ?, ?, ?, ?, ?)`,
                [name, description, category, level, teacherId, max_students], 
                function(err) {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }

            const courseId = this.lastID;
            const stmt = db.prepare(`INSERT INTO schedule (course_id, day, start_time, end_time)
                                      VALUES (?, ?, ?, ?)`);

            schedule.forEach(s => {
                stmt.run([courseId, s.day, s.start_time, s.end_time]);
            });

            stmt.finalize(err => {
                if (err) {
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
                res.json({ success: true, courseId });
            });
        });
    });
});

// Отправка HTML-файла для всех остальных маршрутов
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
