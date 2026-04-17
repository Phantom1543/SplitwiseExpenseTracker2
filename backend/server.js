require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const app = express();
const nodemailer = require("nodemailer");


app.use(express.json());
app.use(cors());

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
}).promise();

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

(async () => {
    try {
        await db.query("SELECT 1");
        console.log("Database connected successfully");
    } catch (error) {
        console.log("Database connection failed:", error);
    }
})();

app.post("/register", async (req, res) => {
    try {

        const { user_name, email, phone_no, user_password } = req.body;

        if (!user_name || !email || !phone_no || !user_password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        // check if user already exists
        const [existingUser] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (existingUser.length > 0) {
            return res.status(409).json({ message: "User already exists" });
        }

        // hash password
        const hashedPassword = await bcrypt.hash(user_password, 10);

        // insert user
        const [result] = await db.query(
            `INSERT INTO users (user_name, email, phone_no, user_password)
             VALUES (?, ?, ?, ?)`,
            [user_name, email, phone_no, hashedPassword]
        );

        return res.status(201).json({
            message: "User registered successfully",
            user_id: result.insertId
        });

    } catch (error) {
        console.log("ERROR:", error);   // 👈 ADD THIS
        return res.status(500).json({ message: "Server error!! Please try again" });
    }
});

app.post("/login", async (req, res) => {
    try {

        const { email, user_password } = req.body;

        const [rows] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const user = rows[0];

        const isMatch = await bcrypt.compare(user_password, user.user_password);

        if (!isMatch) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign(
            { user_id: user.user_id },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        );

        res.json({
            message: "Login successful",
            token
        });

    } catch (error) {
        console.log("LOGIN ERROR:", error);   // 👈 ADD THIS
        return res.status(500).json({ message: "Server error" });
    }
});

const authenticate = (req, res, next) => {

    let token = req.headers.authorization;

    console.log("RAW TOKEN:", token);   // 👈 ADD
    console.log("SECRET:", process.env.JWT_SECRET); // 👈 ADD

    if (!token) {
        return res.status(401).json({ message: "Access denied" });
    }

    if (token.startsWith("Bearer ")) {
        token = token.split(" ")[1];
    }

    console.log("FINAL TOKEN:", token); // 👈 ADD

    try {

        const verified = jwt.verify(token, process.env.JWT_SECRET);

        console.log("VERIFIED:", verified); // 👈 ADD

        req.user = verified;

        next();

    } catch (error) {
        console.log("JWT ERROR:", error); // 👈 IMPORTANT
        res.status(400).json({ message: "Invalid token" });
    }
};

app.get("/profile", authenticate, async (req, res) => {
    try {

        const userId = req.user.user_id;

        const [rows] = await db.query(
            "SELECT user_id, user_name, email, phone_no FROM users WHERE user_id = ?",
            [userId]
        );

        res.json(rows[0]);

    } catch (error) {
        res.status(500).json({ message: "Server error" });
    }
});

app.put("/profile/update", authenticate, async (req, res) => {
    try {

        const userId = req.user.user_id;
        const { user_name, email, phone_no } = req.body;

        if (!user_name && !email && !phone_no) {
            return res.status(400).json({ message: "No data provided to update" });
        }

        const [result] = await db.query(
            `UPDATE users 
             SET user_name = ?, email = ?, phone_no = ?
             WHERE user_id = ?`,
            [user_name, email, phone_no, userId]
        );

        return res.json({
            message: "Profile updated successfully"
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.post("/request-password-change", authenticate, async (req, res) => {
    try {

        const userId = req.user.user_id;
        const { current_password } = req.body;

        if (!current_password) {
            return res.status(400).json({ message: "Current password required" });
        }

        const [rows] = await db.query(
            "SELECT user_password, email FROM users WHERE user_id = ?",
            [userId]
        );

        const user = rows[0];

        const isMatch = await bcrypt.compare(current_password, user.user_password);

        if (!isMatch) {
            return res.status(401).json({ message: "Current password incorrect" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = new Date(Date.now() + 5 * 60 * 1000);

        await db.query(
            "UPDATE users SET reset_otp = ?, otp_expiry = ? WHERE user_id = ?",
            [otp, expiry, userId]
        );

        await transporter.sendMail({
            to: user.email,
            subject: "OTP for Password Change",
            text: `Your OTP is ${otp}. It expires in 5 minutes.`
        });

        return res.json({ message: "OTP sent to email" });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.put("/change-password", authenticate, async (req, res) => {
    try {

        const userId = req.user.user_id;
        const { otp, new_password } = req.body;

        if (!otp || !new_password) {
            return res.status(400).json({ message: "OTP and new password required" });
        }

        const [rows] = await db.query(
            "SELECT reset_otp, otp_expiry FROM users WHERE user_id = ?",
            [userId]
        );

        const user = rows[0];

        if (user.reset_otp !== otp) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        if (new Date() > user.otp_expiry) {
            return res.status(400).json({ message: "OTP expired" });
        }

        const hashedPassword = await bcrypt.hash(new_password, 10);

        await db.query(
            `UPDATE users 
             SET user_password = ?, reset_otp = NULL, otp_expiry = NULL
             WHERE user_id = ?`,
            [hashedPassword, userId]
        );

        return res.json({
            message: "Password changed successfully"
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.post("/forgot-password", async (req, res) => {
    try {

        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: "Email is required" });
        }

        const [rows] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 mins

        await db.query(
            "UPDATE users SET reset_otp = ?, otp_expiry = ? WHERE email = ?",
            [otp, expiry, email]
        );

        await transporter.sendMail({
            to: email,
            subject: "Password Reset OTP",
            text: `Your OTP is ${otp}. It will expire in 5 minutes.`
        });

        return res.json({ message: "OTP sent to email" });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.post("/verify-otp", async (req, res) => {
    try {

        const { email, otp } = req.body;

        const [rows] = await db.query(
            "SELECT reset_otp, otp_expiry FROM users WHERE email = ?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const user = rows[0];

        if (user.reset_otp !== otp) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        if (new Date() > user.otp_expiry) {
            return res.status(400).json({ message: "OTP expired" });
        }

        return res.json({ message: "OTP verified" });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.post("/reset-password", async (req, res) => {
    try {

        const { email, otp, new_password } = req.body;

        if (!email || !otp || !new_password) {
            return res.status(400).json({ message: "All fields required" });
        }

        const [rows] = await db.query(
            "SELECT reset_otp, otp_expiry FROM users WHERE email = ?",
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const user = rows[0];

        if (user.reset_otp !== otp) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        if (new Date() > user.otp_expiry) {
            return res.status(400).json({ message: "OTP expired" });
        }

        const hashedPassword = await bcrypt.hash(new_password, 10);

        await db.query(
            `UPDATE users 
             SET user_password = ?, reset_otp = NULL, otp_expiry = NULL 
             WHERE email = ?`,
            [hashedPassword, email]
        );

        return res.json({ message: "Password reset successful" });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.post("/groups", authenticate, async (req, res) => {
    const connection = await db.getConnection(); // get connection from pool

    try {

        const userId = req.user.user_id;
        const { group_name } = req.body;

        if (!group_name) {
            return res.status(400).json({ message: "Group name is required" });
        }

        await connection.beginTransaction(); // start transaction

        // 1️⃣ Create group
        const [result] = await connection.query(
            `INSERT INTO group_s (group_name, group_members, created_by)
             VALUES (?, ?, ?)`,
            [group_name, userId, userId]
        );

        const groupId = result.insertId;

        // 2️⃣ Add creator as admin
        await connection.query(
            `INSERT INTO group_members (group_id, user_id, group_role)
             VALUES (?, ?, 'Admin')`,
            [groupId, userId]
        );

        await connection.commit(); // ✅ save both queries

        return res.status(201).json({
            message: "Group created successfully",
            group_id: groupId
        });

    } catch (error) {

        await connection.rollback(); // ❌ undo if anything fails

        return res.status(500).json({ message: "Server error" });

    } finally {
        connection.release(); // release connection back to pool
    }
});

app.post("/groups/add-member", authenticate, async (req, res) => {
    try {

        const { group_id, phone_no } = req.body;

        if (!group_id || !phone_no) {
            return res.status(400).json({ message: "Group ID and phone number are required" });
        }

        // ✅ ADD ADMIN CHECK HERE
        const [roleCheck] = await db.query(
            "SELECT group_role FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, req.user.user_id]
        );

        if (roleCheck.length === 0 || roleCheck[0].group_role !== "Admin") {
            return res.status(403).json({ message: "Only admin can add members" });
        }

        // 1️⃣ Find user by phone number
        const [users] = await db.query(
            "SELECT user_id FROM users WHERE phone_no = ?",
            [phone_no]
        );

        if (users.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const newUserId = users[0].user_id;

        // 2️⃣ Check if already member
        const [existing] = await db.query(
            "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, newUserId]
        );

        if (existing.length > 0) {
            return res.status(400).json({ message: "User already in group" });
        }

        // 3️⃣ Add member
        await db.query(
            "INSERT INTO group_members (group_id, user_id) VALUES (?, ?)",
            [group_id, newUserId]
        );

        return res.json({
            message: "Member added successfully"
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/groups/user", authenticate, async (req, res) => {
    try {

        console.log("ROUTE HIT");

        const userId = req.user.user_id;

        const [groups] = await db.query(
            `SELECT g.group_id, g.group_name
             FROM group_members gm
             JOIN group_s g ON gm.group_id = g.group_id
             WHERE gm.user_id = ?
             ORDER BY g.group_id DESC`,
            [userId]
        );

        // ✅ ALWAYS return groups (even empty)
        return res.json({ groups });

    } catch (error) {
        console.log("GROUP ERROR:", error);
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/groups/:group_id", authenticate, async (req, res) => {
    try {

        const { group_id } = req.params;

        if (!group_id) {
            return res.status(400).json({ message: "Group ID is required" });
        }

        const [access] = await db.query(
            "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, req.user.user_id]
        );

        if (access.length === 0) {
            return res.status(403).json({ message: "Access denied" });
        }

        // 1️⃣ Get group info
        const [groupRows] = await db.query(
            "SELECT group_id, group_name, created_by FROM group_s WHERE group_id = ?",
            [group_id]
        );

        if (groupRows.length === 0) {
            return res.status(404).json({ message: "Group not found" });
        }

        // 2️⃣ Get members of the group
        const [members] = await db.query(
            `SELECT u.user_id, u.user_name, u.email, u.phone_no, gm.group_role
             FROM group_members gm
             JOIN users u ON gm.user_id = u.user_id
             WHERE gm.group_id = ?`,
            [group_id]
        );

        return res.json({
            group: groupRows[0],
            members: members
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/groups", authenticate, async (req, res) => {
    try {

        const userId = req.user.user_id;

        const [groups] = await db.query(
            `SELECT 
                g.group_id,
                g.group_name,
                g.created_by,
                gm.group_role,
                COUNT(gm2.user_id) AS total_members
             FROM group_members gm
             JOIN group_s g ON gm.group_id = g.group_id
             JOIN group_members gm2 ON g.group_id = gm2.group_id
             WHERE gm.user_id = ?
             GROUP BY g.group_id, g.group_name, g.created_by, gm.group_role`,
            [userId]
        );

        return res.json({
            groups: groups
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.post("/expenses", authenticate, async (req, res) => {
    const connection = await db.getConnection();

    try {

        const userId = req.user.user_id;

        const {
            group_id,
            amount,
            exp_description,
            split_type,
            members // [{user_id, amount_owed}] for custom OR [{user_id}] for equal
        } = req.body;

        if (!group_id || !amount || !members || members.length === 0) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        // 1️⃣ Check user is part of group
        const [access] = await connection.query(
            "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, userId]
        );

        if (access.length === 0) {
            return res.status(403).json({ message: "Not part of this group" });
        }

        await connection.beginTransaction();

        // 2️⃣ Insert expense
        const [expenseResult] = await connection.query(
            `INSERT INTO expense (group_id, paid_by, paid_for, amount, exp_description)
             VALUES (?, ?, ?, ?, ?)`,
            [group_id, userId, "group", amount, exp_description]
        );

        const expenseId = expenseResult.insertId;

        // 3️⃣ Split logic
        let splitData = [];

        if (split_type === "equal") {

            const splitAmount = amount / members.length;

            splitData = members.map(member => ({
                user_id: member.user_id,
                amount_owed: splitAmount
            }));

        } else if (split_type === "custom") {

            splitData = members;

            // optional validation
            const total = splitData.reduce((sum, m) => sum + m.amount_owed, 0);

            if (total !== amount) {
                throw new Error("Split amounts do not match total");
            }
        }

        // 4️⃣ Insert splits
        for (const m of splitData) {
            await connection.query(
                `INSERT INTO expense_split (expense_id, group_id, user_id, amount_owed)
                 VALUES (?, ?, ?, ?)`,
                [expenseId, group_id, m.user_id, m.amount_owed]
            );
        }

        await connection.commit();

        return res.status(201).json({
            message: "Expense added successfully",
            expense_id: expenseId
        });

    } catch (error) {

        await connection.rollback();

        return res.status(500).json({
            message: error.message || "Server error"
        });

    } finally {
        connection.release();
    }
});

app.get("/groups/:group_id/expenses", authenticate, async (req, res) => {
    try {

        const { group_id } = req.params;
        const userId = req.user.user_id;

        if (!group_id) {
            return res.status(400).json({ message: "Group ID is required" });
        }

        // 🔐 Check access
        const [access] = await db.query(
            "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, userId]
        );

        if (access.length === 0) {
            return res.status(403).json({ message: "Access denied" });
        }

        // 1️⃣ Get expenses
        const [expenses] = await db.query(
            `SELECT 
                e.expense_id,
                e.amount,
                e.exp_description,
                e.exp_date,
                u.user_name AS paid_by_name
             FROM expense e
             JOIN users u ON e.paid_by = u.user_id
             WHERE e.group_id = ?
             ORDER BY e.exp_date DESC`,
            [group_id]
        );

        // ✅ 2️⃣ ADD SPLITS HERE (PRO UPGRADE)
        const [splits] = await db.query(
            `SELECT 
                es.expense_id,
                u.user_name,
                es.amount_owed
             FROM expense_split es
             JOIN users u ON es.user_id = u.user_id
             WHERE es.group_id = ?`,
            [group_id]
        );

        // 3️⃣ Attach splits to each expense
        const formattedExpenses = expenses.map(exp => {
            const expSplits = splits.filter(s => s.expense_id === exp.expense_id);

            return {
                ...exp,
                splits: expSplits
            };
        });

        return res.json({
            expenses: formattedExpenses
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/expenses/:expense_id", authenticate, async (req, res) => {
    try {

        const { expense_id } = req.params;
        const userId = req.user.user_id;

        if (!expense_id) {
            return res.status(400).json({ message: "Expense ID is required" });
        }

        // 1️⃣ Get expense info
        const [expenseRows] = await db.query(
            `SELECT 
                e.expense_id,
                e.group_id,
                e.amount,
                e.exp_description,
                e.exp_date,
                u.user_name AS paid_by_name
             FROM expense e
             JOIN users u ON e.paid_by = u.user_id
             WHERE e.expense_id = ?`,
            [expense_id]
        );

        if (expenseRows.length === 0) {
            return res.status(404).json({ message: "Expense not found" });
        }

        const expense = expenseRows[0];

        // 🔐 2️⃣ Check user is part of this group
        const [access] = await db.query(
            "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
            [expense.group_id, userId]
        );

        if (access.length === 0) {
            return res.status(403).json({ message: "Access denied" });
        }

        // 3️⃣ Get split details
        const [splits] = await db.query(
            `SELECT 
                u.user_id,
                u.user_name,
                es.amount_owed
             FROM expense_split es
             JOIN users u ON es.user_id = u.user_id
             WHERE es.expense_id = ?`,
            [expense_id]
        );

        return res.json({
            expense: expense,
            splits: splits
        });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.post("/settlements", authenticate, async (req, res) => {
    try {

        const { from_user, to_user, amount, group_id } = req.body;

        if (!from_user || !to_user || !amount || !group_id) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        if (from_user === to_user) {
            return res.status(400).json({ message: "Cannot settle with yourself" });
        }

        if (amount <= 0) {
            return res.status(400).json({ message: "Amount must be greater than 0" });
        }

        // ✅ only debtor can settle
        if (req.user.user_id !== from_user) {
            return res.status(403).json({
                message: "Only debtor can settle"
            });
        }

        // ✅ group validation
        const [groupCheck] = await db.query(
            `SELECT COUNT(*) AS count
             FROM group_members 
             WHERE group_id = ? AND user_id IN (?, ?)`,
            [group_id, from_user, to_user]
        );

        if (groupCheck[0].count !== 2) {
            return res.status(403).json({
                message: "Both users must be in same group"
            });
        }

        const [result] = await db.query(
            `INSERT INTO settlements (from_user, to_user, amount, group_id)
             VALUES (?, ?, ?, ?)`,
            [from_user, to_user, amount, group_id]
        );

        return res.json({
            message: "Settlement successful",
            settlement_id: result.insertId
        });

    } catch (error) {
        console.log("SETTLEMENT ERROR:", error);
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/groups/:group_id/settlements", authenticate, async (req, res) => {
    try {

        const { group_id } = req.params;

        const [settlements] = await db.query(
            `SELECT 
                s.settlement_id,
                s.amount,
                s.settle_date,
                u1.user_name AS from_user_name,
                u2.user_name AS to_user_name
             FROM settlements s
             JOIN users u1 ON s.from_user = u1.user_id
             JOIN users u2 ON s.to_user = u2.user_id
             WHERE s.group_id = ?
             ORDER BY s.settle_date DESC`,
            [group_id]
        );

        return res.json({ settlements });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/settlements", authenticate, async (req, res) => {
    try {

        const userId = req.user.user_id;

        const [settlements] = await db.query(
            `SELECT 
                s.settlement_id,
                s.amount,
                s.settle_date,
                u1.user_name AS from_user_name,
                u2.user_name AS to_user_name,
                CASE 
                    WHEN s.from_user = ? THEN 'paid'
                    ELSE 'received'
                END AS type
             FROM settlements s
             JOIN users u1 ON s.from_user = u1.user_id
             JOIN users u2 ON s.to_user = u2.user_id
             WHERE s.from_user = ? OR s.to_user = ?
             ORDER BY s.settle_date DESC`,
            [userId, userId, userId]
        );

        return res.json({ settlements });

    } catch (error) {
        console.log("SETTLEMENT GET ERROR:", error);
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/groups/:group_id/balances", authenticate, async (req, res) => {
    try {

        const { group_id } = req.params;
        const userId = req.user.user_id;

        // 🔐 access check
        const [access] = await db.query(
            "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, userId]
        );

        if (access.length === 0) {
            return res.status(403).json({ message: "Access denied" });
        }

        // ✅ CORRECT BALANCE CALCULATION
        const balanceMap = {};

        const [splits] = await db.query(
            `SELECT e.paid_by, es.user_id, es.amount_owed
             FROM expense e
             JOIN expense_split es ON e.expense_id = es.expense_id
             WHERE e.group_id = ?`,
            [group_id]
        );

        splits.forEach(s => {
            if (s.paid_by !== s.user_id) {
                balanceMap[s.paid_by] = (balanceMap[s.paid_by] || 0) + s.amount_owed;
                balanceMap[s.user_id] = (balanceMap[s.user_id] || 0) - s.amount_owed;
            }
        });

        // ✅ APPLY SETTLEMENTS
        const [settlementRows] = await db.query(
            `SELECT from_user, to_user, amount 
             FROM settlements
             WHERE group_id = ?`,
            [group_id]
        );

        settlementRows.forEach(s => {
            balanceMap[s.from_user] += s.amount;
            balanceMap[s.to_user] -= s.amount;
        });

        // users
        const [users] = await db.query(
            `SELECT u.user_id, u.user_name
             FROM group_members gm
             JOIN users u ON gm.user_id = u.user_id
             WHERE gm.group_id = ?`,
            [group_id]
        );

        const balances = users.map(u => ({
            user_id: u.user_id,
            user_name: u.user_name,
            balance: balanceMap[u.user_id] || 0
        }));

        // ✅ FINAL SETTLEMENT LOGIC
        const settlements = [];

        let creditors = balances.filter(u => u.balance > 0).map(u => ({ ...u }));
        let debtors = balances.filter(u => u.balance < 0).map(u => ({ ...u }));

        creditors.sort((a, b) => b.balance - a.balance);
        debtors.sort((a, b) => a.balance - b.balance);

        let i = 0, j = 0;

        while (i < debtors.length && j < creditors.length) {

            let debtor = debtors[i];
            let creditor = creditors[j];

            let amount = Math.min(
                Math.abs(debtor.balance),
                creditor.balance
            );

            settlements.push({
                from: debtor.user_name,
                to: creditor.user_name,
                from_id: debtor.user_id,
                to_id: creditor.user_id,
                amount: amount
            });

            debtor.balance += amount;
            creditor.balance -= amount;

            if (Math.abs(debtor.balance) < 0.01) i++;
            if (creditor.balance < 0.01) j++;
        }

        return res.json({ balances, settlements });

    } catch (error) {
        console.log("BALANCE ERROR:", error);
        return res.status(500).json({ message: "Server error" });
    }
});

app.put("/expenses/:id", authenticate, async (req, res) => {
    try {

        const { id } = req.params;
        const { amount, exp_description } = req.body;

        if (!amount && !exp_description) {
            return res.status(400).json({ message: "Nothing to update" });
        }

        await db.query(
            `UPDATE expense SET amount = ?, exp_description = ?
             WHERE expense_id = ?`,
            [amount, exp_description, id]
        );

        return res.json({ message: "Expense updated" });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.delete("/expenses/:id", authenticate, async (req, res) => {
    const connection = await db.getConnection();

    try {

        const { id } = req.params;

        await connection.beginTransaction();

        await connection.query(
            "DELETE FROM expense_split WHERE expense_id = ?",
            [id]
        );

        await connection.query(
            "DELETE FROM expense WHERE expense_id = ?",
            [id]
        );

        await connection.commit();

        return res.json({ message: "Expense deleted" });

    } catch (error) {

        await connection.rollback();
        return res.status(500).json({ message: "Server error" });

    } finally {
        connection.release();
    }
});

app.delete("/groups/remove-member", authenticate, async (req, res) => {
    try {

        const { group_id, user_id } = req.body;

        // check admin
        const [admin] = await db.query(
            "SELECT group_role FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, req.user.user_id]
        );

        if (admin[0].group_role !== "Admin") {
            return res.status(403).json({ message: "Only admin can remove members" });
        }

        // ✅ check pending settlements
        const [balances] = await db.query(
            `SELECT SUM(amount_owed) AS total
             FROM expense_split
             WHERE group_id = ?`,
            [group_id]
        );

        if (balances[0].total && balances[0].total > 0) {
            return res.json({ message: "Cannot remove member. Settlements pending." });
        }

        // ✅ prevent admin removing themselves
        if (user_id === req.user.user_id) {
            return res.json({ message: "Admin cannot remove themselves" });
        }

        await db.query(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, user_id]
        );

        return res.json({ message: "Member removed" });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.delete("/groups/leave", authenticate, async (req, res) => {
    try {

        const { group_id, new_admin_id } = req.body;
        const userId = req.user.user_id;

        if (!group_id) {
            return res.status(400).json({ message: "Group ID required" });
        }

        // 1️⃣ Check role
        const [role] = await db.query(
            "SELECT group_role FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, userId]
        );

        if (role.length === 0) {
            return res.status(403).json({ message: "Not part of group" });
        }

        const isAdmin = role[0].group_role === "Admin";

        // 2️⃣ CALCULATE REAL BALANCE
        const [splits] = await db.query(
            `SELECT e.paid_by, es.user_id, es.amount_owed
             FROM expense e
             JOIN expense_split es ON e.expense_id = es.expense_id
             WHERE e.group_id = ?`,
            [group_id]
        );

        let balance = 0;

        splits.forEach(s => {
            if (s.paid_by !== s.user_id) {

                if (s.paid_by === userId) {
                    balance += s.amount_owed;
                }

                if (s.user_id === userId) {
                    balance -= s.amount_owed;
                }
            }
        });

        const [settlements] = await db.query(
            `SELECT from_user, to_user, amount 
             FROM settlements
             WHERE group_id = ?`,
            [group_id]
        );

        settlements.forEach(s => {
            if (s.from_user === userId) {
                balance += s.amount;
            }
            if (s.to_user === userId) {
                balance -= s.amount;
            }
        });

        // ✅ FINAL CHECK
        if (Math.abs(balance) > 0.01) {
            return res.json({ message: "Clear your balances before leaving" });
        }

        // 3️⃣ ADMIN LOGIC
        if (isAdmin) {

            const [members] = await db.query(
                "SELECT user_id FROM group_members WHERE group_id = ?",
                [group_id]
            );

            // ✅ only member → delete group
            if (members.length === 1) {

                await db.query("DELETE FROM expense_split WHERE group_id = ?", [group_id]);
                await db.query("DELETE FROM expense WHERE group_id = ?", [group_id]);
                await db.query("DELETE FROM settlements WHERE group_id = ?", [group_id]); // 🔥 IMPORTANT
                await db.query("DELETE FROM group_members WHERE group_id = ?", [group_id]);
                await db.query("DELETE FROM group_s WHERE group_id = ?", [group_id]);

                return res.json({ message: "Group deleted as no members left" });
            }

            // ✅ assign new admin
            if (!new_admin_id) {
                return res.json({ message: "Assign a new admin before leaving" });
            }

            if (new_admin_id == userId) {
                return res.json({ message: "You are already admin" });
            }

            // ✅ check new admin is in group
            const [checkMember] = await db.query(
                "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
                [group_id, new_admin_id]
            );

            if (checkMember.length === 0) {
                return res.json({ message: "User is not part of this group" });
            }

            await db.query(
                `UPDATE group_members 
                 SET group_role = 'Admin' 
                 WHERE group_id = ? AND user_id = ?`,
                [group_id, new_admin_id]
            );
        }

        // 4️⃣ remove user
        await db.query(
            "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, userId]
        );

        return res.json({ message: "You left the group" });

    } catch (error) {
        console.log("LEAVE ERROR:", error); // 🔥 add this for debugging
        return res.status(500).json({ message: "Server error" });
    }
});

app.get("/groups/:group_id/members", authenticate, async (req, res) => {
    try {

        const { group_id } = req.params;

        const [members] = await db.query(
            `SELECT u.user_id, u.user_name, gm.group_role
             FROM group_members gm
             JOIN users u ON gm.user_id = u.user_id
             WHERE gm.group_id = ?`,
            [group_id]
        );

        return res.json({ members });

    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

app.delete("/groups/:id", authenticate, async (req, res) => {
    const connection = await db.getConnection();

    try {
        const groupId = req.params.id;

        // 1️⃣ Check if user is admin
        const [admin] = await connection.query(
            "SELECT group_role FROM group_members WHERE group_id = ? AND user_id = ?",
            [groupId, req.user.user_id]
        );

        if (admin.length === 0 || admin[0].group_role !== "Admin") {
            return res.status(403).json({ message: "Only admin can delete group" });
        }

        // 2️⃣ Check pending balances
        const [balances] = await connection.query(
            `SELECT 
                SUM(
                    CASE 
                        WHEN e.paid_by != es.user_id THEN es.amount_owed 
                        ELSE 0 
                    END
                ) AS total
             FROM expense_split es
             JOIN expense e ON es.expense_id = e.expense_id
             WHERE es.group_id = ?`,
            [groupId]
        );
        const [settlements] = await connection.query(
            `SELECT SUM(amount) AS total FROM settlements WHERE group_id = ?`,
            [groupId]
        );

        // if settlements exist but not balanced
        if ((balances[0].total || 0) - (settlements[0].total || 0) > 0) {
            return res.json({ message: "Cannot delete group. Settlements pending." });
        }

        await connection.beginTransaction();

        // 3️⃣ Delete related data
        await connection.query("DELETE FROM expense_split WHERE group_id = ?", [groupId]);
        await connection.query("DELETE FROM expense WHERE group_id = ?", [groupId]);
        await connection.query("DELETE FROM group_members WHERE group_id = ?", [groupId]);
        await connection.query("DELETE FROM group_s WHERE group_id = ?", [groupId]);

        await connection.commit();

        return res.json({ message: "Group deleted successfully" });

    } catch (error) {
        await connection.rollback();
        console.log(error);
        return res.status(500).json({ message: "Server error" });
    } finally {
        connection.release();
    }
});

app.put("/groups/change-admin", authenticate, async (req, res) => {
    try {

        const { group_id, new_admin_id } = req.body;
        const userId = req.user.user_id;

        // check current user is admin
        const [role] = await db.query(
            "SELECT group_role FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, userId]
        );

        if (role.length === 0 || role[0].group_role !== "Admin") {
            return res.status(403).json({ message: "Only admin can change admin" });
        }

        // check new admin exists
        const [check] = await db.query(
            "SELECT * FROM group_members WHERE group_id = ? AND user_id = ?",
            [group_id, new_admin_id]
        );

        if (check.length === 0) {
            return res.json({ message: "User is not part of this group" });
        }

        // remove old admin
        await db.query(
            "UPDATE group_members SET group_role = 'Member' WHERE group_id = ? AND user_id = ?",
            [group_id, userId]
        );

        // assign new admin
        await db.query(
            "UPDATE group_members SET group_role = 'Admin' WHERE group_id = ? AND user_id = ?",
            [group_id, new_admin_id]
        );

        return res.json({ message: "Admin changed successfully" });

    } catch (error) {
        console.log("CHANGE ADMIN ERROR:", error);
        return res.status(500).json({ message: "Server error" });
    }
});

app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});