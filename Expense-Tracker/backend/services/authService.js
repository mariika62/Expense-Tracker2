const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Hash Password
async function hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
}

// Verify Password
async function verifyPassword(plaintextPassword, hashedPassword) {
    return await bcrypt.compare(plaintextPassword, hashedPassword);
}

// Generate JWT
function generateToken(payload, secretKey, options) {
    return jwt.sign(payload, secretKey, options);
}

// Verify JWT
function verifyToken(token, secretKey) {
    return jwt.verify(token, secretKey);
}

module.exports = {
    hashPassword,
    verifyPassword,
    generateToken,
    verifyToken
};