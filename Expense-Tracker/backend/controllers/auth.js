const authService = require('../services/authService');
const User = require('../models/userModel');

// Example of a registration endpoint
async function register(req, res) {
    try {
        const { username, password } = req.body;
        const hashedPassword = await authService.hashPassword(password);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error: error.message });
    }
}

// Example of a login endpoint
async function login(req, res) {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const isPasswordValid = await authService.verifyPassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password' });
        }
        const token = authService.generateToken({ username: user.username }, 'your_secret_key', { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
}

module.exports = {
    register,
    login
};