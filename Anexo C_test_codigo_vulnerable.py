#!/usr/bin/env python3
"""
Archivos de prueba con código vulnerable para testing del analizador
SOLO PARA PROPÓSITOS EDUCATIVOS Y DE TESTING
"""

# Crear directorio de pruebas
import os
import shutil

def crear_archivos_prueba():
    """Crea archivos de prueba con vulnerabilidades conocidas"""
    
    # Crear directorio de pruebas
    test_dir = "codigo_prueba"
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)
    
    # 1. Archivo PHP con SQL Injection (API1:2023 - BOLA)
    with open(f"{test_dir}/api_usuarios.php", "w") as f:
        f.write('''<?php
// API vulnerable - Broken Object Level Authorization
header('Content-Type: application/json');

$user_id = $_GET['id']; // Sin validación
$query = "SELECT * FROM users WHERE id = " . $user_id; // SQL Injection
$result = mysql_query($query);

if ($result) {
    $users = array();
    while ($row = mysql_fetch_array($result)) {
        // Exposición excesiva de datos (API3:2023)
        $users[] = array(
            'id' => $row['id'],
            'username' => $row['username'],
            'email' => $row['email'],
            'password_hash' => $row['password'], // ¡Datos sensibles!
            'ssn' => $row['ssn'], // ¡Número de seguridad social!
            'credit_card' => $row['credit_card'] // ¡Tarjeta de crédito!
        );
    }
    echo json_encode($users);
} else {
    echo json_encode(array('error' => mysql_error())); // Exposición de errores
}
?>''')
    
    # 2. Archivo Python con autenticación débil (API2:2023)
    with open(f"{test_dir}/auth_api.py", "w") as f:
        f.write('''from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

# Token hardcodeado - Broken Authentication
SECRET_TOKEN = "admin123"

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Sin validación de entrada
    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    
    # Autenticación débil
    if username == "admin" and password == "password":
        # Token sin expiración
        token = hashlib.md5(username.encode()).hexdigest()
        return jsonify({'token': token, 'role': 'admin'})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/admin/users', methods=['GET'])
def get_users():
    token = request.headers.get('Authorization')
    
    # Sin validación de token
    if not token:
        return jsonify({'error': 'No token provided'}), 401
    
    # Función administrativa sin autorización adecuada (API5:2023)
    users = [
        {'id': 1, 'username': 'admin', 'password': 'password123'},
        {'id': 2, 'username': 'user', 'ssn': '123-45-6789'}
    ]
    
    return jsonify(users)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0') # Configuración insegura
''')
    
    # 3. Archivo JavaScript con SSRF (API7:2023)
    with open(f"{test_dir}/proxy_api.js", "w") as f:
        f.write('''const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());

// API vulnerable a SSRF
app.post('/api/fetch', async (req, res) => {
    const { url } = req.body;
    
    // Sin validación de URL - SSRF vulnerability
    try {
        const response = await axios.get(url);
        res.json({
            status: 'success',
            data: response.data,
            headers: response.headers // Exposición de headers internos
        });
    } catch (error) {
        res.status(500).json({
            error: error.message,
            stack: error.stack // Exposición de stack trace
        });
    }
});

// Sin rate limiting (API4:2023)
app.post('/api/upload', (req, res) => {
    // Sin límite de tamaño de archivo
    const data = req.body.data;
    
    // Procesamiento sin límites
    for (let i = 0; i < 1000000; i++) {
        // Operación costosa sin límites
        Math.random();
    }
    
    res.json({ message: 'File processed' });
});

// Endpoint de debug en producción (API9:2023)
app.get('/api/debug/config', (req, res) => {
    res.json({
        database_url: process.env.DATABASE_URL,
        api_keys: process.env.API_KEYS,
        secret_key: process.env.SECRET_KEY
    });
});

app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on port 3000');
});
''')
    
    # 4. Archivo Java con Mass Assignment (API3:2023)
    with open(f"{test_dir}/UserController.java", "w") as f:
        f.write('''package com.alcaldia.api;

import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/users")
public class UserController {
    
    private List<User> users = new ArrayList<>();
    
    // Mass Assignment vulnerability
    @PostMapping
    public User createUser(@RequestBody User user) {
        // Sin validación de campos
        users.add(user);
        return user;
    }
    
    // Broken Object Level Authorization
    @GetMapping("/{id}")
    public User getUser(@PathVariable String id) {
        // Sin verificación de autorización
        return users.stream()
            .filter(u -> u.getId().equals(id))
            .findFirst()
            .orElse(null);
    }
    
    // Exposición excesiva de datos
    @GetMapping
    public List<User> getAllUsers() {
        // Retorna todos los datos incluyendo sensibles
        return users;
    }
    
    // Sin autenticación en endpoint administrativo
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable String id) {
        users.removeIf(u -> u.getId().equals(id));
    }
}

class User {
    private String id;
    private String username;
    private String password; // Almacenado en texto plano
    private String email;
    private String ssn;
    private boolean isAdmin;
    private String creditCard;
    
    // Getters y setters que permiten modificar cualquier campo
    // incluyendo isAdmin (escalación de privilegios)
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public boolean isAdmin() { return isAdmin; }
    public void setAdmin(boolean admin) { isAdmin = admin; }
    
    // ... otros getters/setters
}
''')
    
    # 5. Archivo de configuración con secretos expuestos (API8:2023)
    with open(f"{test_dir}/config.json", "w") as f:
        f.write('''{
    "database": {
        "host": "localhost",
        "username": "admin",
        "password": "admin123",
        "connection_string": "mysql://admin:admin123@localhost/alcaldia"
    },
    "api_keys": {
        "google_maps": "AIzaSyC4YourRealAPIKeyHere",
        "payment_gateway": "sk_live_51HrealSecretKey",
        "email_service": "SG.realSendGridAPIKey"
    },
    "security": {
        "jwt_secret": "super_secret_key_123",
        "encryption_key": "AES256_KEY_HERE",
        "admin_token": "admin_token_123"
    },
    "debug": true,
    "cors": {
        "allow_all_origins": true,
        "allow_credentials": true
    }
}''')
    
    # 6. Archivo SQL con procedimientos inseguros
    with open(f"{test_dir}/database_procedures.sql", "w") as f:
        f.write('''-- Procedimientos almacenados vulnerables

-- Procedimiento con SQL Injection
DELIMITER //
CREATE PROCEDURE GetUserData(IN user_input VARCHAR(255))
BEGIN
    SET @sql = CONCAT('SELECT * FROM users WHERE username = "', user_input, '"');
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //
DELIMITER ;

-- Procedimiento que expone datos sensibles
DELIMITER //
CREATE PROCEDURE GetAllUserDetails()
BEGIN
    SELECT 
        id,
        username,
        email,
        password_hash,
        ssn,
        credit_card_number,
        bank_account,
        salary,
        personal_notes
    FROM users;
END //
DELIMITER ;

-- Vista que expone información administrativa
CREATE VIEW admin_dashboard AS
SELECT 
    u.username,
    u.email,
    u.last_login,
    u.failed_login_attempts,
    u.account_status,
    p.payment_method,
    p.card_number,
    t.transaction_amount,
    t.transaction_date
FROM users u
LEFT JOIN payments p ON u.id = p.user_id
LEFT JOIN transactions t ON u.id = t.user_id;

-- Función sin validación de permisos
DELIMITER //
CREATE FUNCTION CalculateUserBalance(user_id INT) 
RETURNS DECIMAL(10,2)
READS SQL DATA
BEGIN
    DECLARE balance DECIMAL(10,2);
    SELECT SUM(amount) INTO balance 
    FROM transactions 
    WHERE user_id = user_id;
    RETURN IFNULL(balance, 0);
END //
DELIMITER ;
''')
    
    print(f"Archivos de prueba creados en el directorio: {test_dir}")
    print("Archivos creados:")
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            print(f"  - {os.path.join(root, file)}")
    
    return test_dir

if __name__ == "__main__":
    crear_archivos_prueba()

