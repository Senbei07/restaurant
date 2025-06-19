const express = require('express');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./config');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(express.json()); // เพิ่มบรรทัดนี้เพื่อให้ Express แปลงข้อมูล JSON ใน req.body
app.use(express.urlencoded({ extended: false })); // สำหรับการส่งข้อมูลแบบ urlencoded


// ตั้งค่า session middleware
const sessionMiddleware = session({
    secret: 'mySuperSecretKey123$%^',
    resave: false,
    saveUninitialized: true,
});

dbConnection.getConnection()
    .then(() => console.log('Database connected successfully'))
    .catch(err => console.error('Database connection failed:', err));

app.use(sessionMiddleware);
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
    res.locals.req = req;
    next();
});

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// ให้ socket.io ใช้ session
io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

const storage = multer.diskStorage({
    destination: './uploads', // โฟลเดอร์เก็บรูปภาพ
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // ตั้งชื่อไฟล์ใหม่เป็นเวลาปัจจุบัน + นามสกุลไฟล์
    }
});

const upload = multer({ storage: storage });

// ตัวแปรสำหรับเก็บข้อมูลตะกร้าสินค้า
const cartData = {};

// เส้นทางแสดงหน้า index
app.get('/', (req, res) => {
    res.render('index',);
});






// เส้นทางแสดงหน้าเข้าสู่ระบบ
app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/cart', (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }
    res.render('cart');
});

app.get('/staff_orders', (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }
    res.render('staff_orders');
});


// เส้นทางสำหรับสมัครสมาชิก (GET)
app.get('/signup', async (req, res) => {
    try {
        const [genders] = await dbConnection.execute("SELECT * FROM gender");
        const [titlename] = await dbConnection.execute("SELECT * FROM titlename");
        res.render('signup', { genders, titlename });
    } catch (error) {
        console.error('Error fetching data:', error);
        res.status(500).send('Server Error');
    }
});

// เส้นทางสมัครสมาชิก (POST)
app.post('/signup', async (req, res) => {
    
    const { username, password,c_password ,title_name, name, surname, gender } = req.body;
    console.log({ username, password,c_password ,title_name, name, surname, gender });
    
    try {
        const [existingUser] = await dbConnection.execute("SELECT * FROM login WHERE log_username = ?", [username]);
        

        if (existingUser.length > 0) {
            return res.status(400).send('Username is already in use');
        } else if (password !== c_password) {
            return res.status(400).send('Passwords do not match');
        } else {
            const hashedPassword = await bcrypt.hash(password, 10);
            const [loginResult] = await dbConnection.execute(
                "INSERT INTO login (log_username, log_password, role_id) VALUES (?, ?, ?)",
                [username, hashedPassword, 2]
            );

            const logId = loginResult.insertId;
            await dbConnection.execute(
                "INSERT INTO `user`(`log_id`, `title_id`, `u_name`, `u_surname`, `gender_id`, `u_date`) VALUES (?, ?, ?, ?, ?, NOW())",
                [logId, title_name, name, surname, gender]
            );
            res.status(200).json({ message: 'Signup successful', redirect: '/login' });
        }
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).send('Internal server error');
    }
});

// เส้นทางเข้าสู่ระบบ (POST)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [user] = await dbConnection.execute("SELECT * FROM login INNER JOIN user ON login.log_id = user.log_id WHERE log_username = ?", [username]);

        if (user.length === 0) {
            return res.status(400).json({ message: 'User not found' });
        } else {
            const validPassword = await bcrypt.compare(password, user[0].log_password);
            if (validPassword) {
                req.session.isLoggedIn = true;
                req.session.user = {
                    id: user[0].log_id,
                    u_id: user[0].u_id,
                    role_id: user[0].role_id 
                };
                console.log(req.session.user)
                res.status(200).json({ redirect: '/' });
            } else {
                res.status(400).json({ message: 'Incorrect password' });
            }
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// เส้นทางหน้าร้านค้า
app.get('/order', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }
    try {
        const [products] = await dbConnection.execute(`
            SELECT p.pro_id AS id, p.pro_name AS name, p.pro_img AS img, 
            p.pro_price AS price, pt.pt_name_eng AS category
            FROM products p
            JOIN product_type pt ON p.pt_id = pt.pt_id
        `);

        const [categories] = await dbConnection.execute(`SELECT pt_name_eng AS category FROM product_type`);

        const [promotions] = await dbConnection.execute(`
            SELECT promo_id, promo_name, promo_discount, promo_minimum, promo_maximum,promo_type
            FROM promotion
        `);

        const [user] = await dbConnection.execute("SELECT u_name AS name, u_surname AS surname FROM user WHERE u_id = ?", [req.session.user.u_id]);
        
        res.render('order', { products, categories, promotions, user: user[0] });
    } catch (error) {
        console.error('Error fetching products or user:', error);
        res.status(500).send('Server Error');
    }
});


app.get('/product_add', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }
    try {
        const [products_type] = await dbConnection.execute(
            'SELECT * FROM product_type'
        );
        const [user] = await dbConnection.execute(
            'SELECT u_name AS name, u_surname AS surname FROM user WHERE u_id = ?'
            , [req.session.user.u_id]
        );
        
        res.render('product_add', { products_type, user: user[0] });
    } catch (error) {
        console.error('Error fetching products type or user:', error);
        res.status(500).send('Server Error');
    }
});

app.get('/product_manage', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }
    try {
        // ดึงข้อมูลสินค้า
        const [products] = await dbConnection.execute(`
            SELECT p.pro_id AS id, p.pro_name AS name, p.pro_img AS img, 
            p.pro_price AS price, pt.pt_name_eng AS category
            FROM products p
            JOIN product_type pt ON p.pt_id = pt.pt_id
        `);

        // ดึงข้อมูลผู้ใช้จาก session
        const [user] = await dbConnection.execute("SELECT u_name AS name, u_surname AS surname FROM user WHERE u_id = ?", [req.session.user.u_id]);
        
        res.render('product_manage', { products, user: user[0] });
    } catch (error) {
        console.error('Error fetching products or user:', error);
        res.status(500).send('Server Error');
    }
});

app.get('/product_edit/:id', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }

    const { id } = req.params; // รับ product_id จาก URL

    try {
        // ดึงข้อมูลสินค้าจากฐานข้อมูลโดยใช้ product_id
        const [product] = await dbConnection.execute("SELECT * FROM products WHERE pro_id = ?", [id]);

        // ตรวจสอบว่าพบสินค้าหรือไม่
        if (product.length === 0) {
            return res.status(404).send('Product not found');
        }

        // ดึงข้อมูลประเภทสินค้า
        const [products_type] = await dbConnection.execute('SELECT * FROM product_type');

        // ดึงข้อมูลผู้ใช้
        const [user] = await dbConnection.execute(
            'SELECT u_name AS name, u_surname AS surname FROM user WHERE u_id = ?', [req.session.user.u_id]
        );

        // ส่ง product[0] ไปยังหน้า product_edit
        res.render('product_edit', { product: product[0], products_type, user: user[0] });

    } catch (error) {
        console.error('Product edit error:', error);
        res.status(500).send('Internal server error');
    }
});


app.post('/add-product', upload.single('img'), async (req, res) => {
    const { name, category, price } = req.body;
    const img = req.file ? req.file.filename : null; // ตรวจสอบว่ามีไฟล์รูปภาพหรือไม่

    try {
        // เพิ่มข้อมูลสินค้าใหม่ลงฐานข้อมูล
        await dbConnection.execute(
            "INSERT INTO products (pro_name, pro_img, pro_price, pt_id, pro_date) VALUES (?, ?, ?, ?, NOW())",
            [name, img, price, category]
        );

        res.redirect('/product_add'); // หลังจากเพิ่มเสร็จให้เปลี่ยนไปที่หน้าร้านค้า
    } catch (error) {
        console.error('Error adding product:', error);
        res.status(500).send('Server error');
    }
});

app.post('/update-product/:id', upload.single('img'), async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }

    const { id } = req.params; // รับ product_id จาก URL
    const { name, category, price } = req.body;
    const img = req.file ? req.file.filename : null; // ตรวจสอบว่ามีไฟล์รูปภาพใหม่หรือไม่

    try {
        // ตรวจสอบว่ามีการอัปโหลดรูปภาพใหม่หรือไม่
        if (img) {
            // อัปเดตรวมถึงการเปลี่ยนรูปภาพใหม่
            await dbConnection.execute(
                'UPDATE products SET pro_name = ?, pt_id = ?, pro_price = ?, pro_img = ? WHERE pro_id = ?',
                [name, category, price, img, id]
            );
        } else {
            // อัปเดตเฉพาะข้อมูลอื่นๆ ยกเว้นรูปภาพ
            await dbConnection.execute(
                'UPDATE products SET pro_name = ?, pt_id = ?, pro_price = ? WHERE pro_id = ?',
                [name, category, price, id]
            );
        }

        res.redirect('/order'); // หลังจากอัปเดตเสร็จ เปลี่ยนไปที่หน้าร้านค้า
    } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).send('Server error');
    }
});

app.get('/user_manage', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }
    try {
        // ดึงข้อมูลผู้ใช้
        const [user] = await dbConnection.execute(`
        SELECT u_id,title_name,u_name,u_surname,gender_name,u_point 
        FROM user LEFT JOIN titlename ON user.title_id = titlename.title_id 
        LEFT JOIN gender ON user.gender_id = gender.gender_id;
        `);

        res.render('user_manage', { user });
    } catch (error) {
        console.error('Error fetching products or user:', error);
        res.status(500).send('Server Error');
    }

});

app.get('/user_edit/:id', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }

    const { id } = req.params; // รับ product_id จาก URL

    try {
        // ดึงข้อมูลสินค้าจากฐานข้อมูลโดยใช้ product_id
        const [user_edit] = await dbConnection.execute(`
            SELECT u_id,user.title_id AS title_id,u_name,u_surname,user.gender_id AS gender_id,u_point 
            FROM user LEFT JOIN titlename ON user.title_id = titlename.title_id 
            LEFT JOIN gender ON user.gender_id = gender.gender_id WHERE u_id = ?
            `,[id]);

        // ตรวจสอบว่าพบสินค้าหรือไม่
        if (user_edit.length === 0) {
            return res.status(404).send('User not found');
        }

        // ดึงข้อมูลประเภทสินค้า
        const [genders] = await dbConnection.execute("SELECT * FROM gender");
        const [titlename] = await dbConnection.execute("SELECT * FROM titlename");

        // ส่ง product[0] ไปยังหน้า product_edit
        console.log(user_edit)

        res.render('user_edit', { user_edit: user_edit[0], genders, titlename });

    } catch (error) {
        console.error('User edit error:', error);
        res.status(500).send('Internal server error');
    }
});

app.post('/update-user/:id',  async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }

    const { id } = req.params; // รับ u_id จาก URL
    const { titlename, name, surname, gender, tel } = req.body;
    console.log(id,titlename, name, surname, gender, tel)
    try {
            // อัปเดตเฉพาะข้อมูลอื่นๆ ยกเว้นรูปภาพ
            await dbConnection.execute(
                'UPDATE `user` SET `title_id`=?,`u_name`=?,`u_surname`=?,`gender_id`=? WHERE u_id = ?',
                [titlename, name, surname, gender, tel, id]
            );

        res.redirect('/user_manage'); // หลังจากอัปเดตเสร็จ เปลี่ยนไปที่หน้าร้านค้า
    } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).send('Server error');
    }
});

app.post('/save-promotion', (req, res) => {
    req.session.selectedPromoId = req.body.promoId;
    res.sendStatus(200);
});


app.get('/order-summary', async (req, res) => {
    const sessionId = req.sessionID;
    const cart = cartData[sessionId] || [];
    let total = 0;

    // คำนวณราคารวม
    cart.forEach(item => {
        total += item.price * item.quantity;
    });

    // ดึงโปรโมชันที่ผู้ใช้เลือกไว้จากเซสชัน
    const selectedPromoId = req.session.selectedPromoId || null;
    let promotion = null;
    let discountAmount = 0;
    let finalTotal = total;

    if (selectedPromoId) {
        try {
            // ค้นหาโปรโมชันที่เลือก
            const [promoResult] = await dbConnection.execute(
                `SELECT promo_name, promo_discount, promo_minimum, promo_maximum, promo_type 
                FROM promotion WHERE promo_id = ?`, 
                [selectedPromoId]
            );

            promotion = promoResult[0];
            
            if (promotion && total >= promotion.promo_minimum) {
                // คำนวณส่วนลดตามประเภทโปรโมชัน
                if (promotion.promo_type === 1) {
                    // ส่วนลดแบบเปอร์เซ็นต์
                    discountAmount = Math.min(total * (promotion.promo_discount / 100), promotion.promo_maximum);
                } else if (promotion.promo_type === 2) {
                    // ส่วนลดเป็นจำนวนเงิน
                    discountAmount = Math.min(promotion.promo_discount, promotion.promo_maximum);
                }
                // คำนวณราคารวมหลังหักส่วนลด
                finalTotal = total - discountAmount;
            }
        } catch (error) {
            console.error('Error fetching promotion:', error);
        }
    }

    // ส่งข้อมูลไปยังหน้า order_summary.ejs
    res.render('order_summary', { cart, total, promotion, discountAmount, finalTotal });
});



app.post('/clear-cart', (req, res) => {
    const sessionId = req.sessionID;
    if (cartData[sessionId]) {
        delete cartData[sessionId]; // เคลียร์ข้อมูล cart ของผู้ใช้ปัจจุบัน
    }
    res.sendStatus(200); // ส่งสถานะความสำเร็จกลับไปที่ฝั่งไคลเอนต์
});

// เส้นทางสำหรับยืนยันการสั่งซื้อสินค้า
// ในส่วน confirm-order
app.post('/confirm-order', async (req, res) => {
    const sessionId = req.sessionID;
    const cart = cartData[sessionId] || [];
    let total = 0;

    // คำนวณยอดรวมของสินค้าในตะกร้า
    cart.forEach(item => {
        total += item.price * item.quantity;
    });

    try {
        console.log("Initial Total Amount:", total);
        console.log("User ID:", req.session.user.u_id);

        // ดึงโปรโมชันที่เลือกไว้จากเซสชัน
        const selectedPromoId = req.session.selectedPromoId || null;
        let discountAmount = 0;

        if (selectedPromoId) {
            // ดึงข้อมูลโปรโมชันที่เลือกจากฐานข้อมูล
            const [promoResult] = await dbConnection.execute(
                `SELECT promo_discount, promo_minimum, promo_maximum, promo_type 
                FROM promotion WHERE promo_id = ?`, 
                [selectedPromoId]
            );

            const promotion = promoResult[0];
            if (promotion && total >= promotion.promo_minimum) {
                // คำนวณส่วนลดตามประเภทโปรโมชัน
                if (promotion.promo_type === 1) {
                    // ลดเป็นเปอร์เซ็นต์
                    discountAmount = Math.min((total * promotion.promo_discount) / 100, promotion.promo_maximum);
                } else if (promotion.promo_type === 2) {
                    // ลดเป็นจำนวนเงิน
                    discountAmount = Math.min(promotion.promo_discount, promotion.promo_maximum);
                }

                // ปรับยอดรวมหลังหักส่วนลด
                total -= discountAmount;
            }
        }

        console.log("Final Total after Discount:", total);

        // บันทึกการสั่งซื้อในฐานข้อมูล
        const [orderResult] = await dbConnection.execute(
            'INSERT INTO food_order (u_id, total_price,promo_id, or_date, status_id) VALUES (?, ?, ?, NOW(),1)',
            [req.session.user.u_id, total,req.session.selectedPromoId]
        );
        const orderId = orderResult.insertId;
        console.log("Order ID:", orderId);

        // บันทึกรายการสินค้า
        const orderItemPromises = cart.map(item => {
            return dbConnection.execute(
                'INSERT INTO order_item (or_id, pro_id, ori_detail, ori_quantity) VALUES (?, ?, ?, ?)',
                [orderId, item.id, item.customDetails || item.sweetness || '', item.quantity]
            );
        });
        await Promise.all(orderItemPromises);

        // ส่งข้อมูลออร์เดอร์ใหม่ไปยังพนักงานแบบ real-time
        io.emit('newOrder', { orderId, total, cart });

        // เคลียร์ตะกร้าสินค้า
        delete cartData[sessionId];

        res.sendStatus(200);
    } catch (error) {
        console.error('Error confirming order:', error);
        res.status(500).send('Failed to confirm order');
    }
});



app.get('/status-options', async (req, res) => {
    try {
        const [statuses] = await dbConnection.execute('SELECT status_id AS id, status_name AS name FROM status WHERE status_id >= 2');

        
        // เพิ่ม buttonClass เพื่อใช้กำหนดสีปุ่มในแต่ละสถานะ
        const statusOptions = statuses.map(status => {
            return {
                id: status.id,
                name: status.name,
                buttonClass: status.name === 'Preparing' ? 'btn-warning' : 
                              status.name === 'Completed' ? 'btn-success' : 
                              'btn-secondary'
            };
        });

        res.json(statusOptions);
    } catch (error) {
        console.error('Error fetching status options:', error);
        res.status(500).send('Failed to fetch status options');
    }
});

// เส้นทางสำหรับอัปเดตสถานะออเดอร์
app.post('/update-order-status', async (req, res) => {
    const { orderId, statusId } = req.body;

    try {
        // อัพเดทสถานะของออเดอร์ในตาราง food_order โดยใช้ status_id
        await dbConnection.execute(
            'UPDATE food_order SET status_id = ? WHERE or_id = ?',
            [statusId, orderId]
        );

        // ดึงชื่อสถานะเพื่อแสดงให้ผู้ใช้เห็น
        const [statusResult] = await dbConnection.execute(
            'SELECT status_name FROM status WHERE status_id = ?',
            [statusId]
        );
        
        if (statusResult.length > 0) {
            const statusName = statusResult[0].status_name;
            
            // ส่งการอัปเดตสถานะออเดอร์ไปยังหน้า staff_orders และลูกค้า
            io.emit('orderStatusUpdate', { orderId, status: statusName });
            res.sendStatus(200);
        } else {
            res.status(404).send('Status not found');
        }
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).send('Failed to update order status');
    }
});

app.get('/order_Tracking', (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }
    res.render('order_Tracking', { userId: req.session.user.u_id });
});


// เส้นทางให้ลูกค้าดูรายการออเดอร์ทั้งหมด
app.get('/orders/:userId', async (req, res) => {
    const userId = req.params.userId;

    try {
        const [orders] = await dbConnection.execute(`
            SELECT 
                food_order.or_id AS order_id,
                status.status_name AS status,
                food_order.total_price,
                food_order.promo_id,  -- ส่วนลดที่ใช้
                promotion.promo_name AS promo_name,  -- ชื่อโปรโมชัน
                products.pro_name,
                order_item.ori_quantity AS quantity,
                products.pro_price AS price,
                order_item.ori_detail AS detail
            FROM food_order
            LEFT JOIN order_item ON food_order.or_id = order_item.or_id
            LEFT JOIN products ON order_item.pro_id = products.pro_id
            LEFT JOIN status ON food_order.status_id = status.status_id
            LEFT JOIN promotion ON food_order.promo_id = promotion.promo_id  -- เชื่อมตาราง promotion
            WHERE food_order.u_id = ?
            ORDER BY food_order.or_id DESC
        `, [userId]);

        const ordersGrouped = Object.values(
            orders.reduce((acc, order) => {
                const { order_id, status, total_price, discount_amount, promo_name, pro_name, quantity, price, detail } = order;
                if (!acc[order_id]) {
                    acc[order_id] = { order_id, status, total_price, discount_amount, promo_name, items: [] };
                }
                acc[order_id].items.push({ pro_name, quantity, price, detail });
                return acc;
            }, {})
        );

        res.json(ordersGrouped);
    } catch (error) {
        console.error('Error fetching orders:', error);
        res.status(500).json({ message: 'Failed to fetch orders' });
    }
});




// Endpoint สำหรับอัปเดตสถานะคำสั่งซื้อ
app.post('/update-order-status', async (req, res) => {
    const { orderId, status } = req.body;

    try {
        await dbConnection.execute(
            'UPDATE food_order SET status = ? WHERE or_id = ?',
            [status, orderId]
        );

        io.emit('orderStatusUpdate', { orderId, status });
        res.sendStatus(200);
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).send('Failed to update order status');
    }
});

app.get('/order_history', async (req, res) => {
    if (!req.session.isLoggedIn) {
        return res.redirect('/login');
    }

    try {
        // SQL query to retrieve order history with order details
        const [orders] = await dbConnection.execute(`
            SELECT 
                food_order.or_id AS order_id,
                CONCAT(title_name, ' ', user.u_name, ' ', user.u_surname) AS customer_name,
                GROUP_CONCAT(CONCAT(products.pro_name, ' x ', order_item.ori_quantity) SEPARATOR ', ') AS ordered_items,
                food_order.or_date AS order_date,
                food_order.total_price AS total_amount
            FROM 
                food_order
            JOIN 
                order_item ON food_order.or_id = order_item.or_id
            JOIN 
                user ON food_order.u_id = user.u_id
            JOIN 
                titlename ON user.title_id = titlename.title_id
            JOIN 
                products ON order_item.pro_id = products.pro_id
            GROUP BY 
                food_order.or_id
            ORDER BY 
                food_order.or_date DESC
        `);

        res.render('order_history', { orders });
    } catch (error) {
        console.error('Error fetching order history:', error);
        res.status(500).send('Internal server error');
    }
});

// เส้นทางสำหรับ Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error clearing session:', err);
            return res.status(500).send('Failed to log out');
        }
        res.redirect('/login'); // หลังจาก logout จะนำไปที่หน้า login
    });
});


app.delete('/product_delete/:id', async (req, res) => {
    const { id } = req.params; // ดึง id ของสินค้าจาก URL

    try {
        // ลบสินค้าจากฐานข้อมูล
        const [result] = await dbConnection.execute('DELETE FROM products WHERE pro_id = ?', [id]);

        if (result.affectedRows > 0) {
            res.sendStatus(200); // ส่งการตอบกลับว่าลบสำเร็จ
            console.log(`Product with ID ${id} deleted successfully.`);
        } else {
            res.status(404).send('Product not found'); // หากไม่พบสินค้าให้ส่ง 404
        }
    } catch (error) {
        console.error('Error deleting product:', error);
        res.status(500).send('Failed to delete product'); // ส่งข้อผิดพลาดกลับไปยังไคลเอนต์
    }
});

app.delete('/user_delete/:user_id', async (req, res) => {
    const { user_id } = req.params;

    try {
        // ค้นหา log_id ที่เชื่อมโยงกับ user ที่จะลบ
        const [user] = await dbConnection.execute('SELECT log_id FROM user WHERE u_id = ?', [user_id]);

        if (user.length > 0) {
            const log_id = user[0].log_id;

            // ลบข้อมูลจากตาราง user
            await dbConnection.execute('DELETE FROM user WHERE u_id = ?', [user_id]);

            // ลบข้อมูลจากตาราง login โดยอ้างอิงจาก log_id
            await dbConnection.execute('DELETE FROM login WHERE log_id = ?', [log_id]);

            res.sendStatus(200); // ส่งสถานะความสำเร็จกลับไปยังฝั่งไคลเอนต์
        } else {
            res.sendStatus(404); // กรณีไม่พบข้อมูลผู้ใช้ ส่งสถานะ 404 Not Found
        }
    } catch (error) {
        console.error('Error deleting user and login:', error);
        res.sendStatus(500); // ส่งสถานะล้มเหลวในกรณีที่เกิดข้อผิดพลาด
    }
});


// ใช้ socket.io สำหรับการจัดการตะกร้าสินค้า
io.on('connection', (socket) => {
    console.log('User connected');

    // Fetch and group orders by order_id, calculating discounts as needed
    async function fetchGroupedOrders() {
        const [orders] = await dbConnection.execute(`
            SELECT 
                food_order.or_id AS order_id,
                food_order.total_price,
                promotion.promo_name AS promotion,
                promotion.promo_discount AS discount,
                promotion.promo_type AS promo_type,
                promotion.promo_maximum AS promo_maximum,
                status.status_name AS status,
                order_item.ori_detail AS detail, 
                order_item.ori_quantity AS quantity, 
                products.pro_name AS pro_name, 
                products.pro_price AS price 
            FROM food_order 
            LEFT JOIN order_item ON food_order.or_id = order_item.or_id 
            LEFT JOIN products ON order_item.pro_id = products.pro_id 
            LEFT JOIN promotion ON food_order.promo_id = promotion.promo_id
            LEFT JOIN status ON food_order.status_id = status.status_id;
        `);

        return groupOrdersById(orders);
    }

    // Fetch and group a single order by order_id, calculating discounts as needed
    async function fetchOrderById(orderId) {
        const [orders] = await dbConnection.execute(`
            SELECT 
                food_order.or_id AS order_id,
                food_order.total_price,
                promotion.promo_name AS promotion,
                promotion.promo_discount AS discount,
                promotion.promo_type AS promo_type,
                promotion.promo_maximum AS promo_maximum,
                status.status_name AS status,
                order_item.ori_detail AS detail, 
                order_item.ori_quantity AS quantity, 
                products.pro_name AS pro_name, 
                products.pro_price AS price 
            FROM food_order 
            LEFT JOIN order_item ON food_order.or_id = order_item.or_id 
            LEFT JOIN products ON order_item.pro_id = products.pro_id 
            LEFT JOIN promotion ON food_order.promo_id = promotion.promo_id
            LEFT JOIN status ON food_order.status_id = status.status_id
            WHERE food_order.or_id = ?;
        `, [orderId]);

        const grouped = groupOrdersById(orders);
        return Object.values(grouped)[0];
    }

    // Helper function to group orders by `order_id` and calculate discount
    function groupOrdersById(orders) {
        return orders.reduce((acc, order) => {
            const { order_id, total_price, discount, promo_type, promo_maximum, promotion, status } = order;
            let discountAmount = 0;

            // Calculate discount based on promo_type and promo_maximum
            if (promo_type === 1) {
                discountAmount = Math.min((total_price * (discount / 100)), promo_maximum);
            } else if (promo_type === 2) {
                discountAmount = Math.min(discount, promo_maximum);
            }

            // Initialize order object if not already present
            if (!acc[order_id]) {
                acc[order_id] = {
                    order_id,
                    total_price,
                    discountAmount,
                    promotion,
                    status,
                    items: []
                };
            }

            // Add each product item to the order
            acc[order_id].items.push({
                pro_name: order.pro_name,
                quantity: order.quantity,
                price: order.price,
                detail: order.detail
            });

            return acc;
        }, {});
    }

    // Function to broadcast all orders to all clients
    async function broadcastAllOrders() {
        const orders = await fetchGroupedOrders();
        io.emit('newOrderData', Object.values(orders));
    }

    // Emit all orders when a new connection is made
    broadcastAllOrders();

    // Handle new orders and broadcast all orders
    socket.on('new_order', () => {
        broadcastAllOrders();
    });

    // Update order status and notify clients in real-time
    socket.on('updateStatus', async ({ orderId, statusId }) => {
        try {
            await dbConnection.execute(`UPDATE food_order SET status_id = ? WHERE or_id = ?`, [statusId, orderId]);
            
            // Fetch and broadcast the updated order only
            const updatedOrder = await fetchOrderById(orderId);
            io.emit('orderStatusUpdate', updatedOrder); // Emit updated order

        } catch (error) {
            console.error('Error updating order status:', error);
        }
    });

    socket.on('addToCart', async ({ productId, sweetness, productPrice, customDetails }) => {
        const sessionId = socket.request.sessionID;
        if (!cartData[sessionId]) cartData[sessionId] = [];

        // ค้นหาสินค้าในตะกร้าที่มีรายละเอียดตรงกัน (รวม customDetails และ sweetness)
        const productIndex = cartData[sessionId].findIndex(item => 
            item.id === productId && item.sweetness === sweetness && item.customDetails === customDetails
        );

        if (productIndex >= 0) {
            // หากพบสินค้าเดิมในตะกร้าที่มีรายละเอียดตรงกัน ให้เพิ่มจำนวน
            cartData[sessionId][productIndex].quantity += 1;
        } else {
            // หากยังไม่มีสินค้าในตะกร้าพร้อมรายละเอียดนี้ ให้เพิ่มใหม่
            const [product] = await dbConnection.execute("SELECT * FROM products WHERE pro_id = ?", [productId]);
            if (product.length > 0) {
                const { pro_name: name } = product[0];
                cartData[sessionId].push({ 
                    id: productId, 
                    name, 
                    price: productPrice, 
                    sweetness, 
                    customDetails, 
                    quantity: 1 
                });
            }
        }
        socket.emit('updateCart', cartData[sessionId]);
    });

    socket.on('updateQuantity', ({ productId, action }) => {
        const sessionId = socket.request.sessionID;
        const cart = cartData[sessionId];
        const productIndex = cart.findIndex(item => item.id === productId);

        if (productIndex >= 0) {
            if (action === 'increase') {
                cart[productIndex].quantity += 1;
            } else if (action === 'decrease') {
                cart[productIndex].quantity -= 1;
                if (cart[productIndex].quantity <= 0) {
                    cart.splice(productIndex, 1);
                }
            }
            socket.emit('updateCart', cart); // ส่งข้อมูลตะกร้ากลับไปยังฝั่งไคลเอนต์
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected');
    });
});



server.listen(3000, () => {
    console.log("Server is running on port 3000...");
}).on('error', (err) => {
    console.error('Error starting server:', err);
});