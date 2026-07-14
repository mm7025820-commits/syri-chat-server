const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');
const WebSocket = require('ws');
const http = require('http');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ===== الإعدادات =====
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'SYRI_CHAT_SUPER_SECRET_KEY_2025';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com';

// ===== قاعدة البيانات =====
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'syri_chat',
    password: process.env.DB_PASSWORD || 'your_password',
    port: process.env.DB_PORT || 5432,
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== تخزين OTP مؤقت =====
const otpStore = {};

// ===== مجلد uploads =====
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// ===== Multer =====
const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// ===== Google OAuth Client =====
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// ===== مسار رئيسي =====
app.get('/', (req, res) => {
    res.send('🚀 SYRI Chat Server is running!');
});

// ===== مصادقة التوكن =====
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'مطلوب توكن' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'توكن غير صالح' });
        req.user = user;
        next();
    });
};

// ============================================================
// ===== نقاط النهاية (Endpoints) =====
// ============================================================

// 1. تسجيل الدخول عبر جوجل
app.post('/api/auth/google', async (req, res) => {
    const { idToken } = req.body;
    try {
        const ticket = await client.verifyIdToken({
            idToken,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const googleId = payload['sub'];
        const email = payload['email'];
        const name = payload['name'];
        const picture = payload['picture'];

        const result = await pool.query(
            'SELECT * FROM users WHERE google_id = $1',
            [googleId]
        );

        if (result.rows.length > 0) {
            const user = result.rows[0];
            return res.json({
                status: 'exists',
                usernameHint: user.username,
                displayName: user.display_name,
                avatar: user.avatar_url
            });
        } else {
            return res.json({
                status: 'new',
                googleData: { googleId, email, name, picture }
            });
        }
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(400).json({ error: 'فشل التحقق من جوجل' });
    }
});

// 2. تسجيل مستخدم جديد
app.post('/api/auth/register', async (req, res) => {
    const { googleId, email, displayName, username, password, avatarUrl, phone } = req.body;
    try {
        const check = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        if (check.rows.length > 0) {
            return res.status(400).json({ error: 'اسم المستخدم محجوز' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO users 
             (google_id, email, display_name, username, password_hash, avatar_url, phone) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) 
             RETURNING id, username, display_name, avatar_url, email`,
            [googleId || null, email, displayName, username, hashedPassword, avatarUrl || null, phone || null]
        );

        const user = result.rows[0];
        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        await pool.query(
            'INSERT INTO user_settings (user_id) VALUES ($1)',
            [user.id]
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                avatarUrl: user.avatar_url,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'فشل التسجيل' });
    }
});

// 3. تسجيل دخول المستخدم الموجود
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE username = $1',
            [username]
        );
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'اسم مستخدم أو كلمة مرور خاطئة' });
        }

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) {
            return res.status(401).json({ error: 'اسم مستخدم أو كلمة مرور خاطئة' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        const messages = await pool.query(
            `SELECT * FROM messages 
             WHERE sender_id = $1 OR receiver_id = $1 
             ORDER BY sent_at DESC LIMIT 50`,
            [user.id]
        );

        const settings = await pool.query(
            'SELECT * FROM user_settings WHERE user_id = $1',
            [user.id]
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                displayName: user.display_name,
                avatarUrl: user.avatar_url,
                email: user.email
            },
            messages: messages.rows,
            settings: settings.rows[0] || {}
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'فشل تسجيل الدخول' });
    }
});

// 4. إرسال رمز التحقق (OTP)
app.post('/api/auth/send-otp', async (req, res) => {
    const { phone } = req.body;
    if (!phone) {
        return res.status(400).json({ error: 'رقم الهاتف مطلوب' });
    }
    const otp = Math.floor(100000 + Math.random() * 900000);
    otpStore[phone] = otp.toString();
    console.log(`📱 OTP for ${phone}: ${otp}`);
    res.json({ success: true, otp: otp.toString() });
});

// 5. التحقق من رمز OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    const { phone, otp } = req.body;
    if (!phone || !otp) {
        return res.status(400).json({ error: 'رقم الهاتف والرمز مطلوبان' });
    }
    const storedOtp = otpStore[phone];
    if (storedOtp && storedOtp === otp) {
        delete otpStore[phone];
        res.json({ success: true });
    } else {
        res.status(400).json({ error: 'رمز غير صحيح' });
    }
});

// 6. رفع الملفات
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'لم يتم رفع أي ملف' });
    }
    const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
    const fileUrl = `${baseUrl}/uploads/${req.file.filename}`;
    res.json({ success: true, fileUrl });
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 7. البحث عن مستخدمين (NEW)
app.get('/api/users/search', authenticateToken, async (req, res) => {
    const { q } = req.query;
    if (!q || q.length < 2) {
        return res.json([]);
    }
    try {
        const result = await pool.query(
            `SELECT id, username, display_name, avatar_url 
             FROM users 
             WHERE username ILIKE $1 AND id != $2
             LIMIT 20`,
            [`%${q}%`, req.user.userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).json({ error: 'فشل البحث' });
    }
});

// 8. إضافة صديق (NEW)
app.post('/api/users/add-friend', authenticateToken, async (req, res) => {
    const { friendId } = req.body;
    const userId = req.user.userId;
    try {
        // التحقق من وجود المستخدم
        const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [friendId]);
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }
        // إضافة رسالة ترحيب أو إنشاء محادثة
        // هنا نضيف سجل في جدول المحادثات (إذا لم تكن موجودة)
        // يمكننا إرسال رسالة ترحيب تلقائية
        res.json({ success: true });
    } catch (error) {
        console.error('Add friend error:', error);
        res.status(500).json({ error: 'فشل إضافة الصديق' });
    }
});

// 9. جلب قائمة المحادثات (الأصدقاء) (NEW)
app.get('/api/users/friends', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const result = await pool.query(
            `SELECT DISTINCT 
                u.id, u.username, u.display_name, u.avatar_url,
                u.is_online,
                (SELECT content FROM messages 
                 WHERE (sender_id = u.id AND receiver_id = $1) 
                    OR (sender_id = $1 AND receiver_id = u.id) 
                 ORDER BY sent_at DESC LIMIT 1) as last_message,
                (SELECT sent_at FROM messages 
                 WHERE (sender_id = u.id AND receiver_id = $1) 
                    OR (sender_id = $1 AND receiver_id = u.id) 
                 ORDER BY sent_at DESC LIMIT 1) as last_message_time
             FROM users u
             JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = $1) 
                               OR (m.receiver_id = u.id AND m.sender_id = $1)
             WHERE u.id != $1
             ORDER BY last_message_time DESC`,
            [userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Friends error:', error);
        res.status(500).json({ error: 'فشل جلب المحادثات' });
    }
});

// 10. التحقق من توفر اسم المستخدم
app.get('/api/users/check-username', async (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(400).json({ error: 'اسم المستخدم مطلوب' });
    }
    try {
        const result = await pool.query(
            'SELECT id FROM users WHERE username = $1',
            [username]
        );
        res.json({ available: result.rows.length === 0 });
    } catch (error) {
        res.status(500).json({ error: 'فشل التحقق' });
    }
});

// 11. تحديث حالة الاتصال
app.post('/api/users/status', authenticateToken, async (req, res) => {
    const { isOnline } = req.body;
    try {
        await pool.query(
            'UPDATE users SET is_online = $1, last_active = NOW() WHERE id = $2',
            [isOnline, req.user.userId]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Status error:', error);
        res.status(500).json({ error: 'فشل تحديث الحالة' });
    }
});

// 12. جلب المحادثات الكاملة بين مستخدمين
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    const otherUserId = req.params.userId;
    const myId = req.user.userId;
    try {
        const result = await pool.query(
            `SELECT * FROM messages 
             WHERE (sender_id = $1 AND receiver_id = $2) 
                OR (sender_id = $2 AND receiver_id = $1) 
             ORDER BY sent_at ASC`,
            [myId, otherUserId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Messages error:', error);
        res.status(500).json({ error: 'فشل جلب المحادثة' });
    }
});

// ===== WebSocket =====
const clients = new Map();

wss.on('connection', (ws, req) => {
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            
            if (data.type === 'auth') {
                const token = data.token;
                const decoded = jwt.verify(token, JWT_SECRET);
                const userId = decoded.userId;
                clients.set(userId, ws);
                ws.userId = userId;
                broadcastStatus(userId, true);
                const unread = await pool.query(
                    `SELECT * FROM messages 
                     WHERE receiver_id = $1 AND is_read = false`,
                    [userId]
                );
                ws.send(JSON.stringify({
                    type: 'unread_messages',
                    messages: unread.rows
                }));
            }

            if (data.type === 'message') {
                const { receiverId, content, messageType, fileUrl } = data;
                const senderId = ws.userId;
                const result = await pool.query(
                    `INSERT INTO messages 
                     (sender_id, receiver_id, content, message_type, file_url) 
                     VALUES ($1, $2, $3, $4, $5) 
                     RETURNING id, sent_at`,
                    [senderId, receiverId, content, messageType || 'text', fileUrl || null]
                );
                const newMessage = {
                    id: result.rows[0].id,
                    sender_id: senderId,
                    receiver_id: receiverId,
                    content,
                    message_type: messageType || 'text',
                    file_url: fileUrl || null,
                    sent_at: result.rows[0].sent_at,
                    is_read: false
                };
                const receiverWs = clients.get(receiverId);
                if (receiverWs && receiverWs.readyState === WebSocket.OPEN) {
                    receiverWs.send(JSON.stringify({
                        type: 'new_message',
                        message: newMessage
                    }));
                }
                ws.send(JSON.stringify({
                    type: 'message_sent',
                    message: newMessage
                }));
            }

            if (data.type === 'read_receipt') {
                const { messageId } = data;
                await pool.query(
                    'UPDATE messages SET is_read = true WHERE id = $1',
                    [messageId]
                );
                const messageResult = await pool.query(
                    'SELECT sender_id FROM messages WHERE id = $1',
                    [messageId]
                );
                const senderId = messageResult.rows[0].sender_id;
                const senderWs = clients.get(senderId);
                if (senderWs) {
                    senderWs.send(JSON.stringify({
                        type: 'message_read',
                        messageId
                    }));
                }
            }
        } catch (error) {
            console.error('WebSocket error:', error);
            ws.send(JSON.stringify({ type: 'error', message: 'فشل معالجة الطلب' }));
        }
    });

    ws.on('close', async () => {
        if (ws.userId) {
            clients.delete(ws.userId);
            broadcastStatus(ws.userId, false);
            await pool.query(
                'UPDATE users SET is_online = false WHERE id = $1',
                [ws.userId]
            );
        }
    });
});

async function broadcastStatus(userId, isOnline) {
    try {
        const friends = await pool.query(
            `SELECT DISTINCT 
                CASE 
                    WHEN sender_id = $1 THEN receiver_id 
                    ELSE sender_id 
                END AS friend_id 
             FROM messages 
             WHERE sender_id = $1 OR receiver_id = $1`,
            [userId]
        );
        for (const row of friends.rows) {
            const friendWs = clients.get(row.friend_id);
            if (friendWs && friendWs.readyState === WebSocket.OPEN) {
                friendWs.send(JSON.stringify({
                    type: 'user_status',
                    userId,
                    isOnline
                }));
            }
        }
    } catch (error) {
        console.error('broadcastStatus error:', error);
    }
}

// ===== تشغيل الخادم =====
server.listen(PORT, () => {
    console.log(`🚀 SYRI Chat Server running on port ${PORT}`);
    console.log(`📍 WebSocket server ready`);
});
