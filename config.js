const mysql = require("mysql2");
const dbConnection = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "gojo_restaurant"
}).promise();

module.exports = dbConnection;
