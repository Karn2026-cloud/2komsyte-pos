// index.js - KOMSYTE Backend (Fully Updated for Recurring Subscriptions)

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const multer = require('multer');
const XLSX = require('xlsx');
const nodemailer = require('nodemailer');
require('dotenv').config();

// ---------------- App Setup ----------------
const app = express();

// Use express.json() BEFORE the webhook route
// The webhook needs the raw body, so we conditionally apply the json parser.
app.use((req, res, next) => {
  if (req.path === '/api/razorpay-webhook') {
    // We use express.raw() for the webhook route to validate the signature
    return express.raw({ type: 'application/json' })(req, res, next);
  }
  return express.json()(req, res, next);
});

// index.js - KOMSYTE Backend (Ready for Hosting)

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
// ... other imports remain the same
require('dotenv').config();

// ...

// ✅ PERFECTED CORS CONFIGURATION FOR HOSTING
const allowedOrigins = [
  // For local development
  'http://localhost:3000',
  'http://localhost:5173',
  
  // For your live Vercel frontend.
  // This value should be set in your Render environment variables.
  process.env.FRONTEND_URL 
].filter(Boolean); // .filter(Boolean) removes any falsy values like null or undefined

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true
}));

// ... The rest of your backend code remains exactly the same

// ---------------- MongoDB ----------------
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// ---------------- Constants ----------------
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_jwt_secret';
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET || ''; // Add this to your .env file
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

// ✅ Map your internal plan keys to the Plan IDs from your Razorpay Dashboard
const RAZORPAY_PLAN_IDS = {
  '299':  'plan_YOUR_299_PLAN_ID',  // 👈 REPLACE WITH YOUR 299 PLAN ID
  '699':  'plan_YOUR_699_PLAN_ID',  // 👈 REPLACE WITH YOUR 699 PLAN ID
  '1499': 'plan_YOUR_1499_PLAN_ID'  // 👈 REPLACE WITH YOUR 1499 PLAN ID
};

const PLANS = {
  free: {
    name: 'Free',
    price: 0,
    maxProducts: 10,
    features: {
      billingHistory: true, downloadBill: false, updateQuantity: false,
      reports: 'none', whatsappShare: false, emailShare: false,
      lowStockAlert: false, manualAdd: false, topProduct: false
    }
  },
  '299': {
    name: 'Basic', price: 299, maxProducts: 50,
    features: {
      billingHistory: true, downloadBill: true, updateQuantity: true,
      reports: 'simple', whatsappShare: false, emailShare: false,
      lowStockAlert: false, manualAdd: false, topProduct: false
    }
  },
  '699': {
    name: 'Growth', price: 699, maxProducts: 100,
    features: {
      billingHistory: true, downloadBill: true, updateQuantity: true,
      reports: 'all', whatsappShare: true, emailShare: false,
      lowStockAlert: true, manualAdd: true, topProduct: true
    }
  },
  '1499': {
    name: 'Premium', price: 1499, maxProducts: Infinity,
    features: {
      billingHistory: true, downloadBill: true, updateQuantity: true,
      reports: 'all', whatsappShare: true, emailShare: true,
      lowStockAlert: true, manualAdd: true, topProduct: true
    }
  }
};

// ---------------- Razorpay Setup ----------------
const razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });

// ---------------- Nodemailer Setup ----------------
const transporter = (EMAIL_USER && EMAIL_PASS) ? nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS }
}) : null;

// ---------------- Schemas (Updated) ----------------
const subscriptionSchema = new mongoose.Schema({
  plan: { type: String, enum: Object.keys(PLANS), default: 'free' },
  status: { type: String, enum: ['inactive', 'active', 'canceled', 'halted'], default: 'active' },
  startDate: Date,
  nextBillingDate: Date,
  razorpayPaymentId: String,
  razorpaySubscriptionId: String, // ✅ Essential field to link to Razorpay
}, { _id: false });

const shopSchema = new mongoose.Schema({
  shopName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  subscription: { type: subscriptionSchema, default: () => ({ plan: 'free', status: 'active' }) }, // ✅ Free plan is active on signup
}, { timestamps: true });

const productSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  barcode: { type: String, required: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true },
}, { timestamps: true });
productSchema.index({ shopId: 1, barcode: 1 }, { unique: true });

const billSchema = new mongoose.Schema({
  shopId: { type: mongoose.Schema.Types.ObjectId, ref: 'Shop', required: true },
  receiptNo: { type: String, required: true },
  items: [{ barcode: String, name: String, price: Number, quantity: Number, subtotal: Number }],
  totalAmount: Number,
  customerMobile: String,
}, { timestamps: true });

const Shop = mongoose.model('Shop', shopSchema);
const Product = mongoose.model('Product', productSchema);
const Bill = mongoose.model('Bill', billSchema);

// ---------------- Middleware ----------------
function authMiddleware(req, res, next) {
    try {
      const auth = req.headers.authorization || '';
      if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token provided' });
      
      const token = auth.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      
      req.shopId = decoded.shopId;
      next();
    } catch (err) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function subscriptionMiddleware(requiredPlans = []) {
    return async (req, res, next) => {
        try {
            const shop = await Shop.findById(req.shopId);
            if (!shop) return res.status(404).json({ error: 'Shop not found' });
      
            const planKey = shop.subscription?.plan || 'free';
            const planConfig = PLANS[planKey];
            if (!planConfig) return res.status(400).json({ error: 'Invalid plan configured' });
      
            if (requiredPlans.length && !requiredPlans.includes(planKey)) {
              return res.status(403).json({ error: `Feature available only for ${requiredPlans.join(', ')} plan(s).` });
            }
      
            if (planKey !== 'free' && shop.subscription?.status !== 'active') {
              return res.status(403).json({ error: 'Subscription is not active. Please check your payment status.' });
            }
      
            req.planConfig = planConfig;
            req.planKey = planKey;
            next();
        } catch (err) {
            res.status(500).json({ error: 'Server error checking subscription' });
        }
    };
}

const upload = multer({ storage: multer.memoryStorage() });

// ---------------- Auth Routes ----------------
app.post('/api/signup', async (req, res) => {
    try {
        const { shopName, email, password } = req.body;
        if (!shopName || !email || !password) return res.status(400).json({ error: 'All fields required' });
        if (await Shop.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: 'Email already registered' });
    
        const hashedPassword = await bcrypt.hash(password, 10);
        const shop = await new Shop({ shopName, email: email.toLowerCase(), password: hashedPassword }).save();
        const token = jwt.sign({ shopId: shop._id }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Server error during signup' });
    }
});
  
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
        const shop = await Shop.findOne({ email: email.toLowerCase() });
        if (!shop || !(await bcrypt.compare(password, shop.password))) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
    
        const token = jwt.sign({ shopId: shop._id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Server error during login' });
    }
});
  
app.get('/api/me', authMiddleware, async (req, res) => {
    try {
        const shop = await Shop.findById(req.shopId).select('-password');
        if (!shop) return res.status(404).json({ error: 'Shop not found' });
        res.json(shop);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});


// ---------------- Subscription Routes (REBUILT) ----------------

app.get('/api/plans', (_, res) => res.json({ plans: Object.values(PLANS).map((p, i) => ({ id: Object.keys(PLANS)[i], ...p })) }));

// STEP 1: Create a subscription
app.post("/api/create-subscription", authMiddleware, async (req, res) => {
    try {
        const { plan } = req.body;
        const planId = RAZORPAY_PLAN_IDS[plan];
        if (!planId) return res.status(400).json({ error: "Invalid plan selected" });

        const shop = await Shop.findById(req.shopId);
        if (!shop) return res.status(404).json({ error: "Shop not found" });

        const subscription = await razorpay.subscriptions.create({
            plan_id: planId,
            customer_notify: 1,
            total_count: 12, // Authorize for 12 monthly payments
        });

        shop.subscription.plan = plan;
        shop.subscription.razorpaySubscriptionId = subscription.id;
        shop.subscription.status = 'inactive'; // Becomes 'active' after first payment via webhook
        await shop.save();

        res.json({
            key_id: RAZORPAY_KEY_ID,
            subscription_id: subscription.id,
        });

    } catch (err) {
        console.error("Create subscription error:", err);
        res.status(500).json({ error: "Failed to create subscription" });
    }
});

// STEP 2: Listen for webhook events from Razorpay
app.post("/api/razorpay-webhook", async (req, res) => {
    const secret = RAZORPAY_WEBHOOK_SECRET;
    const signature = req.headers['x-razorpay-signature'];

    try {
        // The body needs to be a string for validation
        const shasum = crypto.createHmac('sha256', secret);
        shasum.update(req.body.toString());
        const digest = shasum.digest('hex');

        if (digest === signature) {
            // The request is authentic, now parse the body
            const eventData = JSON.parse(req.body.toString());
            const event = eventData.event;
            const payload = eventData.payload;
            console.log(`✅ Webhook received for event: ${event}`);

            const subscriptionId = payload.subscription.entity.id;
            const shop = await Shop.findOne({ 'subscription.razorpaySubscriptionId': subscriptionId });

            if (!shop) {
                console.log(`Webhook Error: Shop not found for subscription ID ${subscriptionId}`);
                return res.json({ status: 'error', message: 'Shop not found' });
            }

            if (event === 'subscription.charged') {
                shop.subscription.status = 'active';
                shop.subscription.razorpayPaymentId = payload.payment.entity.id;
                shop.subscription.nextBillingDate = new Date(payload.subscription.entity.charge_at * 1000);
                if (!shop.subscription.startDate) shop.subscription.startDate = new Date();
                
                await shop.save();
                console.log(`✅ Subscription for ${shop.shopName} successfully charged and renewed.`);
            }
            
            if (event === 'subscription.halted') {
                shop.subscription.status = 'halted';
                await shop.save();
                console.log(`⚠️ Subscription for ${shop.shopName} has been halted due to payment failure.`);
            }

            res.json({ status: 'ok' });

        } else {
            res.status(400).send('Invalid webhook signature');
        }
    } catch(error) {
        console.error("Webhook processing error:", error);
        res.status(500).send('Webhook processing error');
    }
});


// ---------------- Products Routes ----------------
app.post('/api/products', authMiddleware, subscriptionMiddleware(), async (req, res) => {
    try {
        const { barcode, name, price, quantity, updateStock } = req.body;
        if (!barcode) return res.status(400).json({ error: 'Barcode is required.' });

        const planConfig = req.planConfig;
        let product = await Product.findOne({ shopId: req.shopId, barcode });

        if (updateStock) {
            if (!planConfig.features.updateQuantity) return res.status(403).json({ error: 'Updating stock is not available on your plan.' });
            if (!product) return res.status(404).json({ error: 'Product not found.' });

            product.quantity += Number(quantity);
            await product.save();
            return res.json({ message: 'Stock updated successfully', product });
        } else {
            if (product) return res.status(409).json({ error: 'Product with this barcode already exists.' });
            if ((await Product.countDocuments({ shopId: req.shopId })) >= planConfig.maxProducts) {
                return res.status(403).json({ error: `You have reached your product limit of ${planConfig.maxProducts}. Please upgrade.` });
            }
            const newProduct = new Product({ shopId: req.shopId, barcode, name, price, quantity });
            await newProduct.save();
            return res.status(201).json({ message: 'Product added successfully', product: newProduct });
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error handling product' });
    }
});

app.post('/api/stock/upload', authMiddleware, subscriptionMiddleware(['299', '699', '1499']), upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
        const sheet = XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]]);
        if (!sheet.length) return res.status(400).json({ error: 'Excel file is empty' });
        
        const planMax = req.planConfig.maxProducts;
        let productCount = await Product.countDocuments({ shopId: req.shopId });
        const results = [];
  
        for (const row of sheet) {
            const { barcode, name, price, quantity } = row;
            if (!barcode || !name || price == null || quantity == null) {
                results.push({ barcode, status: 'skipped', reason: 'Missing fields' });
                continue;
            }
    
            let product = await Product.findOne({ shopId: req.shopId, barcode });
            if (product) {
                if (req.planConfig.features.updateQuantity) {
                    product.quantity += Number(quantity);
                    await product.save();
                    results.push({ barcode, status: 'updated' });
                } else {
                    results.push({ barcode, status: 'skipped', reason: 'Plan does not allow stock updates.' });
                }
            } else {
                if (productCount >= planMax) {
                    results.push({ barcode, status: 'skipped', reason: `Plan limit reached (${planMax} products)` });
                    continue;
                }
                await new Product({ shopId: req.shopId, barcode, name, price: Number(price), quantity: Number(quantity) }).save();
                productCount++;
                results.push({ barcode, status: 'added' });
            }
        }
        res.json({ message: 'Bulk upload completed', results });
    } catch (err) {
        res.status(500).json({ error: 'Server error during bulk upload' });
    }
});

app.delete('/api/stock/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const product = await Product.findOneAndDelete({ _id: id, shopId: req.shopId });
        if (!product) return res.status(404).json({ error: 'Product not found' });
        res.json({ message: 'Product deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/stock', authMiddleware, async (req, res) => {
    try {
        const products = await Product.find({ shopId: req.shopId });
        res.json(products);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch stock' });
    }
});


// ---------------- Billing Routes ----------------
app.post('/api/bills', authMiddleware, subscriptionMiddleware(), async (req, res) => {
    const session = await mongoose.startSession();
    try {
        let finalBill;
        await session.withTransaction(async () => {
            const { items, customerMobile } = req.body;
            if (!items || !Array.isArray(items) || items.length === 0) {
                throw new Error('No items provided');
            }
            
            const planConfig = req.planConfig;
            const billItems = [];
            let computedTotal = 0;
      
            for (const it of items) {
                if (it.barcode) { // Item from inventory
                    const product = await Product.findOne({ shopId: req.shopId, barcode: it.barcode }).session(session);
                    if (!product) throw new Error(`Product not found: ${it.barcode}`);
                    if (product.quantity < it.quantity) throw new Error(`Insufficient stock for ${product.name}`);
        
                    const subtotal = product.price * it.quantity;
                    billItems.push({ ...it, price: product.price, name: product.name, subtotal });
                    computedTotal += subtotal;
        
                    await Product.updateOne(
                        { _id: product._id },
                        { $inc: { quantity: -it.quantity } },
                        { session }
                    );
                } else { // Manually added item
                    if (!planConfig.features.manualAdd) throw new Error('Your plan does not allow adding manual products to bills.');
                    const subtotal = it.price * it.quantity;
                    billItems.push({ ...it, subtotal });
                    computedTotal += subtotal;
                }
            }
    
            const shop = await Shop.findById(req.shopId).session(session);
            const receiptNo = `INV-${shop.shopName.substring(0,3).toUpperCase()}-${Date.now()}`;
            
            const bill = new Bill({
                shopId: req.shopId,
                receiptNo,
                items: billItems,
                totalAmount: computedTotal,
                customerMobile: customerMobile || null,
            });
            finalBill = await bill.save({ session });
        });
        
        session.endSession();
        res.status(201).json({ message: 'Bill finalized successfully', bill: finalBill });
  
    } catch (err) {
        if (session.inTransaction()) {
            await session.abortTransaction();
        }
        session.endSession();
        res.status(500).json({ error: err.message || 'Server error while finalizing bill' });
    }
});
  
app.get('/api/bills', authMiddleware, async (req, res) => {
    try {
        const bills = await Bill.find({ shopId: req.shopId }).sort({ createdAt: -1 }).limit(200);
        res.json(bills);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch bills' });
    }
});

// ---------------- Start Server ----------------
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));



