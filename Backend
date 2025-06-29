// financial_dashboard_backend/index.ts
// Node.js + TypeScript backend with JWT, MongoDB, CSV export for your Financial Analytics Dashboard

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import { Parser } from 'json2csv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret_key';

mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/financial_dashboard', {
}).then(() => console.log('MongoDB connected')).catch(err => console.error(err));

// User Schema and Model
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
});
const User = mongoose.model('User', userSchema);

// Transaction Schema and Model
const transactionSchema = new mongoose.Schema({}, { strict: false });
const Transaction = mongoose.model('Transaction', transactionSchema);

// Auth Routes
app.post('/auth/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.json({ message: 'User registered' });
});

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
});

// Auth middleware
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'No token' });
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = decoded;
        next();
    });
};

// Transactions API with filters, sort, pagination
app.get('/transactions', authMiddleware, async (req, res) => {
    const { page = 1, limit = 10, sortField = 'date', sortOrder = 'desc', ...filters } = req.query;
    const skip = (Number(page) - 1) * Number(limit);

    const query = {};
    if (filters.category) query['category'] = filters.category;
    if (filters.status) query['status'] = filters.status;
    if (filters.user_id) query['user_id'] = filters.user_id;
    if (filters.minAmount && filters.maxAmount) {
        query['amount'] = { $gte: Number(filters.minAmount), $lte: Number(filters.maxAmount) };
    }

    const transactions = await Transaction.find(query)
        .sort({ [sortField]: sortOrder === 'desc' ? -1 : 1 })
        .skip(skip)
        .limit(Number(limit));
    res.json(transactions);
});

// CSV Export
app.post('/export', authMiddleware, async (req, res) => {
    const { columns, filters = {} } = req.body;
    const query = {};
    if (filters.category) query['category'] = filters.category;
    if (filters.status) query['status'] = filters.status;
    if (filters.user_id) query['user_id'] = filters.user_id;

    const transactions = await Transaction.find(query);
    const data = transactions.map(txn => {
        const filtered = {};
        columns.forEach(col => filtered[col] = txn[col]);
        return filtered;
    });

    const parser = new Parser({ fields: columns });
    const csv = parser.parse(data);
    res.header('Content-Type', 'text/csv');
    res.attachment('transactions.csv');
    return res.send(csv);
});

// Seed Route for transactions.json (run once)
import fs from 'fs';
app.get('/seed', async (req, res) => {
    const raw = fs.readFileSync('./transactions.json');
    const transactions = JSON.parse(raw.toString());
    await Transaction.insertMany(transactions);
    res.json({ message: 'Transactions seeded successfully' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
