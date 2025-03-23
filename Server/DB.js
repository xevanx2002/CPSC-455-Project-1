import mysql from 'mysql2/promise';

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Rhune10',
    database: 'chatdb',
    connectionLimit: 10,
    queueLimit: 0
});

export default pool;