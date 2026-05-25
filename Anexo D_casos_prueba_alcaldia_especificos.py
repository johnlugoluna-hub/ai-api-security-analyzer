#!/usr/bin/env python3
"""
Casos de Prueba Específicos para Alcaldías
Proyecto: Análisis de Vulnerabilidades en APIs Gubernamentales
Estudiante: John Lugo - UNAD
Descripción: Casos de prueba específicos para el contexto de alcaldías colombianas
"""

import os
import shutil
from datetime import datetime

def crear_casos_alcaldia():
    """Crea casos de prueba específicos para APIs de alcaldías"""
    
    # Crear directorio específico
    test_dir = "casos_prueba_alcaldia"
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)
    
    print(f" Creando casos de prueba específicos para Alcaldía de Ibagué...")
    print(f" Directorio: {test_dir}")
    
    # 1. API de Consulta de Predial (Caso muy común en alcaldías)
    with open(f"{test_dir}/api_predial.php", "w") as f:
        f.write('''<?php
/**
 * API de Consulta de Impuesto Predial - Alcaldía de Ibagué
 * VULNERABILIDADES TÍPICAS EN SISTEMAS GUBERNAMENTALES
 */
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Configuración CORS insegura

// Conexión a base de datos con credenciales hardcodeadas (API8:2023)
$host = "localhost";
$username = "alcaldia_user";
$password = "Ibague2024!"; // Contraseña en código fuente
$database = "sistema_predial";

$conexion = new mysqli($host, $username, $password, $database);

// Obtener número de predio sin validación (API1:2023 - BOLA)
$numero_predio = $_GET['predio']; // Sin sanitización
$cedula_propietario = $_GET['cedula']; // Sin validación de autorización

// Consulta SQL vulnerable a inyección (API1:2023)
$query = "SELECT p.numero_predio, p.direccion, p.avaluo_catastral, 
                 p.area_terreno, p.area_construida, p.estrato,
                 pr.nombres, pr.apellidos, pr.cedula, pr.telefono,
                 pr.email, pr.ingresos_declarados, pr.estado_civil,
                 i.valor_impuesto, i.descuentos, i.intereses_mora,
                 i.fecha_vencimiento, i.estado_pago
          FROM predios p 
          JOIN propietarios pr ON p.id_propietario = pr.id
          JOIN impuestos i ON p.id = i.id_predio
          WHERE p.numero_predio = '" . $numero_predio . "'"; // SQL Injection

$resultado = $conexion->query($query);

if ($resultado && $resultado->num_rows > 0) {
    $datos = array();
    while ($fila = $resultado->fetch_assoc()) {
        // Exposición excesiva de datos personales (API3:2023)
        $datos[] = array(
            'numero_predio' => $fila['numero_predio'],
            'direccion_completa' => $fila['direccion'],
            'avaluo_catastral' => $fila['avaluo_catastral'],
            'propietario_cedula' => $fila['cedula'], // Dato sensible expuesto
            'propietario_nombres' => $fila['nombres'],
            'propietario_telefono' => $fila['telefono'], // Información personal
            'propietario_email' => $fila['email'],
            'ingresos_declarados' => $fila['ingresos_declarados'], // Información financiera sensible
            'estado_civil' => $fila['estado_civil'], // Dato personal innecesario
            'valor_impuesto' => $fila['valor_impuesto'],
            'descuentos_aplicados' => $fila['descuentos'],
            'intereses_mora' => $fila['intereses_mora'],
            'fecha_vencimiento' => $fila['fecha_vencimiento'],
            'estado_pago' => $fila['estado_pago']
        );
    }
    
    // Respuesta sin filtrado por autorización (API1:2023)
    // Cualquier persona puede consultar predios de otros
    echo json_encode($datos);
    
} else {
    // Exposición de información de base de datos en errores (API8:2023)
    echo json_encode(array(
        'error' => 'No se encontraron datos',
        'query_ejecutada' => $query, // Exposición de consulta SQL
        'error_mysql' => $conexion->error // Error de base de datos expuesto
    ));
}

// Sin límites de consultas (API4:2023)
// Un atacante puede hacer miles de consultas sin restricciones

$conexion->close();
?>''')
    
    # 2. API de Certificados y Documentos (Muy sensible en alcaldías)
    with open(f"{test_dir}/api_certificados.py", "w") as f:
        f.write('''"""
API de Expedición de Certificados - Alcaldía de Ibagué
VULNERABILIDADES EN PROCESOS ADMINISTRATIVOS CRÍTICOS
"""
from flask import Flask, request, jsonify, send_file
import os
import hashlib
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuración insegura (API8:2023)
app.config['DEBUG'] = True  # Debug habilitado en producción
app.config['SECRET_KEY'] = 'alcaldia_ibague_2024'  # Clave secreta hardcodeada

# Token de administrador hardcodeado (API2:2023)
ADMIN_TOKEN = "admin_alcaldia_2024"
FUNCIONARIO_TOKEN = "funcionario_123"

@app.route('/api/certificados/solicitar', methods=['POST'])
def solicitar_certificado():
    """Solicitud de certificados - Vulnerable a abuso automatizado"""
    
    data = request.get_json()
    tipo_certificado = data.get('tipo')
    cedula_solicitante = data.get('cedula')
    
    # Sin rate limiting (API4:2023 y API6:2023)
    # Un bot puede solicitar miles de certificados
    
    # Sin validación de entrada (API3:2023)
    if not cedula_solicitante or not tipo_certificado:
        return jsonify({'error': 'Datos incompletos'}), 400
    
    # Sin verificación de autorización (API1:2023)
    # Cualquiera puede solicitar certificados de cualquier persona
    
    # Generación de certificado sin validación de identidad
    numero_certificado = hashlib.md5(f"{cedula_solicitante}{datetime.now()}".encode()).hexdigest()
    
    # Almacenamiento inseguro de información sensible
    certificado_data = {
        'numero': numero_certificado,
        'tipo': tipo_certificado,
        'cedula_ciudadano': cedula_solicitante,
        'fecha_expedicion': datetime.now().isoformat(),
        'funcionario_expedidor': 'SISTEMA_AUTOMATICO',
        'estado': 'EXPEDIDO'
    }
    
    return jsonify({
        'mensaje': 'Certificado expedido exitosamente',
        'certificado': certificado_data,
        'url_descarga': f'/api/certificados/descargar/{numero_certificado}'
    })

@app.route('/api/certificados/descargar/<numero_certificado>')
def descargar_certificado(numero_certificado):
    """Descarga de certificados - Vulnerable a acceso no autorizado"""
    
    # Sin validación de autorización (API1:2023)
    # Cualquiera con el número puede descargar el certificado
    
    # Path traversal potential (API7:2023)
    ruta_archivo = f"/var/certificados/{numero_certificado}.pdf"
    
    # Sin validación de existencia o permisos
    try:
        return send_file(ruta_archivo, as_attachment=True)
    except Exception as e:
        # Exposición de rutas del sistema (API8:2023)
        return jsonify({
            'error': 'Error accediendo al archivo',
            'ruta_intentada': ruta_archivo,
            'error_sistema': str(e)
        }), 500

@app.route('/api/admin/certificados', methods=['GET'])
def listar_todos_certificados():
    """Función administrativa - Vulnerable a escalación de privilegios"""
    
    token = request.headers.get('Authorization')
    
    # Validación de token débil (API2:2023 y API5:2023)
    if not token:
        return jsonify({'error': 'Token requerido'}), 401
    
    # Sin validación robusta de roles
    if token not in [ADMIN_TOKEN, FUNCIONARIO_TOKEN]:
        return jsonify({'error': 'Token inválido'}), 403
    
    # Exposición masiva de datos (API3:2023)
    # Retorna información sensible de todos los certificados
    certificados = [
        {
            'numero': 'CERT001',
            'tipo': 'Residencia',
            'cedula_ciudadano': '12345678',
            'nombres_completos': 'Juan Pérez García',
            'direccion_residencia': 'Calle 15 #23-45, Ibagué',
            'telefono': '3001234567',
            'email': 'juan.perez@email.com',
            'ingresos_declarados': 2500000,
            'fecha_expedicion': '2024-09-15'
        },
        {
            'numero': 'CERT002',
            'tipo': 'Ingresos y Retenciones',
            'cedula_ciudadano': '87654321',
            'nombres_completos': 'María González López',
            'salario_base': 3200000,
            'deducciones': 450000,
            'retenciones_aplicadas': 180000,
            'fecha_expedicion': '2024-09-16'
        }
    ]
    
    return jsonify(certificados)

@app.route('/api/certificados/validar', methods=['POST'])
def validar_certificado():
    """Validación de certificados - Vulnerable a SSRF"""
    
    data = request.get_json()
    url_validacion = data.get('url_validacion_externa')
    
    # SSRF vulnerability (API7:2023)
    if url_validacion:
        import requests
        try:
            # Sin validación de URL - puede atacar sistemas internos
            response = requests.get(url_validacion, timeout=30)
            return jsonify({
                'validacion_externa': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers)  # Exposición de headers internos
            })
        except Exception as e:
            return jsonify({
                'error': 'Error en validación externa',
                'url_intentada': url_validacion,
                'error_detalle': str(e)
            }), 500
    
    return jsonify({'error': 'URL de validación requerida'}), 400

if __name__ == '__main__':
    # Configuración insegura para producción (API8:2023)
    app.run(debug=True, host='0.0.0.0', port=5000)
''')
    
    # 3. API de Pagos en Línea (Crítico para alcaldías)
    with open(f"{test_dir}/api_pagos_linea.js", "w") as f:
        f.write('''/**
 * API de Pagos en Línea - Alcaldía de Ibagué
 * VULNERABILIDADES EN SISTEMAS DE PAGO GUBERNAMENTALES
 */

const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json({ limit: '50mb' })); // Sin límite apropiado (API4:2023)

// Configuración de base de datos insegura (API8:2023)
const DB_CONFIG = {
    host: 'localhost',
    user: 'pagos_user',
    password: 'PagosAlcaldia2024!', // Contraseña hardcodeada
    database: 'sistema_pagos',
    port: 3306
};

// Claves de pasarelas de pago expuestas (API8:2023)
const PAYMENT_KEYS = {
    pse_key: 'PSE_ALCALDIA_IBAGUE_2024_SECRET',
    credit_card_key: 'CC_PROCESSOR_SECRET_KEY_12345',
    bank_transfer_key: 'BANK_API_SECRET_ALCALDIA'
};

// Endpoint de pago sin rate limiting (API4:2023 y API6:2023)
app.post('/api/pagos/procesar', async (req, res) => {
    const {
        cedula_pagador,
        tipo_impuesto,
        valor_pago,
        metodo_pago,
        numero_tarjeta,
        cvv,
        fecha_expiracion
    } = req.body;
    
    // Sin validación de autorización (API1:2023)
    // Cualquiera puede pagar impuestos de otros sin verificación
    
    // Sin validación de entrada (API3:2023)
    if (!cedula_pagador || !valor_pago) {
        return res.status(400).json({
            error: 'Datos incompletos',
            datos_recibidos: req.body // Exposición de datos sensibles en logs
        });
    }
    
    // Procesamiento sin límites (API4:2023)
    // Sin verificar si el valor es razonable o si hay múltiples intentos
    
    // Almacenamiento inseguro de datos de tarjeta (API8:2023)
    const transaccion = {
        id: crypto.randomUUID(),
        cedula_pagador: cedula_pagador,
        valor: valor_pago,
        metodo: metodo_pago,
        tarjeta_numero: numero_tarjeta, // Almacena número completo de tarjeta
        tarjeta_cvv: cvv, // Almacena CVV en texto plano
        tarjeta_expiracion: fecha_expiracion,
        fecha_transaccion: new Date().toISOString(),
        estado: 'PROCESANDO'
    };
    
    // Simulación de procesamiento con pasarela externa (API10:2023)
    try {
        const resultado_pago = await procesarPagoExterno(transaccion);
        
        // Exposición excesiva de datos en respuesta (API3:2023)
        res.json({
            mensaje: 'Pago procesado exitosamente',
            transaccion_completa: transaccion, // Incluye datos sensibles
            resultado_pasarela: resultado_pago,
            claves_internas: PAYMENT_KEYS, // Exposición accidental de claves
            configuracion_db: DB_CONFIG // Exposición de configuración
        });
        
    } catch (error) {
        // Exposición de errores internos (API8:2023)
        res.status(500).json({
            error: 'Error procesando pago',
            error_detalle: error.message,
            stack_trace: error.stack,
            transaccion_fallida: transaccion
        });
    }
});

// Función vulnerable de procesamiento externo (API10:2023)
async function procesarPagoExterno(transaccion) {
    const axios = require('axios');
    
    // URL de pasarela construida dinámicamente (API7:2023)
    const gateway_url = `https://pasarela-pagos.gov.co/procesar?callback=${req.body.callback_url}`;
    
    // Sin validación de respuesta externa (API10:2023)
    const response = await axios.post(gateway_url, {
        amount: transaccion.valor,
        card_number: transaccion.tarjeta_numero,
        cvv: transaccion.tarjeta_cvv,
        api_key: PAYMENT_KEYS.credit_card_key
    });
    
    // Confianza ciega en respuesta externa
    return response.data;
}

// Endpoint administrativo sin autenticación (API5:2023)
app.get('/api/admin/transacciones', (req, res) => {
    // Sin verificación de permisos administrativos
    const todas_transacciones = [
        {
            id: 'TXN001',
            cedula: '12345678',
            nombres: 'Juan Pérez',
            valor: 150000,
            tarjeta: '4532-1234-5678-9012', // Número de tarjeta expuesto
            cvv: '123', // CVV expuesto
            fecha: '2024-09-15'
        },
        {
            id: 'TXN002',
            cedula: '87654321',
            nombres: 'María González',
            valor: 320000,
            tarjeta: '5555-4444-3333-2222',
            cvv: '456',
            fecha: '2024-09-16'
        }
    ];
    
    res.json({
        total_transacciones: todas_transacciones.length,
        transacciones: todas_transacciones,
        estadisticas_internas: {
            servidor: process.env,
            configuracion: DB_CONFIG
        }
    });
});

// Endpoint de webhook vulnerable (API7:2023)
app.post('/api/webhook/pago-confirmado', (req, res) => {
    const { callback_url, transaction_data } = req.body;
    
    // SSRF a través de callback (API7:2023)
    if (callback_url) {
        const axios = require('axios');
        axios.post(callback_url, transaction_data)
            .then(response => {
                res.json({
                    mensaje: 'Webhook procesado',
                    respuesta_callback: response.data
                });
            })
            .catch(error => {
                res.status(500).json({
                    error: 'Error en callback',
                    url_intentada: callback_url,
                    datos_enviados: transaction_data
                });
            });
    }
});

// Configuración insegura del servidor (API8:2023)
app.listen(3000, '0.0.0.0', () => {
    console.log('API de Pagos ejecutándose en puerto 3000');
    console.log('Configuración DB:', DB_CONFIG); // Log de credenciales
    console.log('Claves de pago:', PAYMENT_KEYS); // Log de claves sensibles
});
''')
    
    # 4. Sistema de Gestión de Funcionarios (Interno crítico)
    with open(f"{test_dir}/sistema_funcionarios.java", "w") as f:
        f.write('''/**
 * Sistema de Gestión de Funcionarios - Alcaldía de Ibagué
 * VULNERABILIDADES EN SISTEMAS ADMINISTRATIVOS INTERNOS
 */
package com.alcaldia.ibague.funcionarios;

import org.springframework.web.bind.annotation.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import java.util.*;
import java.sql.*;

@SpringBootApplication
@RestController
@RequestMapping("/api/funcionarios")
public class SistemaFuncionarios {
    
    // Credenciales de base de datos hardcodeadas (API8:2023)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/rrhh_alcaldia";
    private static final String DB_USER = "admin_rrhh";
    private static final String DB_PASSWORD = "AlcaldiaRRHH2024!";
    
    // Token de administrador hardcodeado (API2:2023)
    private static final String ADMIN_TOKEN = "ADMIN_ALCALDIA_2024";
    
    public static void main(String[] args) {
        SpringApplication.run(SistemaFuncionarios.class, args);
    }
    
    // Endpoint vulnerable a inyección SQL (API1:2023)
    @GetMapping("/consultar/{cedula}")
    public Map<String, Object> consultarFuncionario(@PathVariable String cedula,
                                                   @RequestParam(required = false) String token) {
        
        // Sin validación de autorización (API1:2023)
        // Cualquier funcionario puede consultar datos de otros
        
        Map<String, Object> resultado = new HashMap<>();
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // Consulta SQL vulnerable (API1:2023)
            String query = "SELECT f.cedula, f.nombres, f.apellidos, f.cargo, f.salario, " +
                          "f.fecha_ingreso, f.estado, f.telefono, f.email, f.direccion, " +
                          "f.contacto_emergencia, f.eps, f.arl, f.pension, " +
                          "e.evaluacion_desempeño, e.observaciones_disciplinarias, " +
                          "n.numero_cuenta, n.banco, n.tipo_cuenta " +
                          "FROM funcionarios f " +
                          "LEFT JOIN evaluaciones e ON f.id = e.id_funcionario " +
                          "LEFT JOIN nomina n ON f.id = n.id_funcionario " +
                          "WHERE f.cedula = '" + cedula + "'"; // SQL Injection
            
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            List<Map<String, Object>> funcionarios = new ArrayList<>();
            
            while (rs.next()) {
                Map<String, Object> funcionario = new HashMap<>();
                
                // Exposición excesiva de datos sensibles (API3:2023)
                funcionario.put("cedula", rs.getString("cedula"));
                funcionario.put("nombres_completos", rs.getString("nombres") + " " + rs.getString("apellidos"));
                funcionario.put("cargo", rs.getString("cargo"));
                funcionario.put("salario_base", rs.getDouble("salario")); // Información salarial sensible
                funcionario.put("fecha_ingreso", rs.getDate("fecha_ingreso"));
                funcionario.put("estado_laboral", rs.getString("estado"));
                funcionario.put("telefono_personal", rs.getString("telefono"));
                funcionario.put("email_personal", rs.getString("email"));
                funcionario.put("direccion_residencia", rs.getString("direccion")); // Dirección personal
                funcionario.put("contacto_emergencia", rs.getString("contacto_emergencia")); // Datos familiares
                funcionario.put("eps", rs.getString("eps"));
                funcionario.put("arl", rs.getString("arl"));
                funcionario.put("fondo_pension", rs.getString("pension"));
                funcionario.put("evaluacion_desempeño", rs.getString("evaluacion_desempeño")); // Información laboral sensible
                funcionario.put("observaciones_disciplinarias", rs.getString("observaciones_disciplinarias")); // Información disciplinaria
                funcionario.put("numero_cuenta_bancaria", rs.getString("numero_cuenta")); // Información financiera crítica
                funcionario.put("banco", rs.getString("banco"));
                funcionario.put("tipo_cuenta", rs.getString("tipo_cuenta"));
                
                funcionarios.add(funcionario);
            }
            
            resultado.put("funcionarios", funcionarios);
            resultado.put("total_encontrados", funcionarios.size());
            
            // Exposición de información de consulta (API8:2023)
            resultado.put("query_ejecutada", query);
            resultado.put("servidor_bd", DB_URL);
            
            conn.close();
            
        } catch (SQLException e) {
            // Exposición de errores de base de datos (API8:2023)
            resultado.put("error", "Error consultando base de datos");
            resultado.put("error_sql", e.getMessage());
            resultado.put("error_code", e.getErrorCode());
            resultado.put("sql_state", e.getSQLState());
        }
        
        return resultado;
    }
    
    // Mass assignment vulnerability (API3:2023)
    @PostMapping("/crear")
    public Map<String, Object> crearFuncionario(@RequestBody Map<String, Object> datosFuncionario) {
        
        // Sin validación de autorización (API5:2023)
        // Sin validación de campos permitidos (API3:2023)
        // Un usuario podría asignarse rol de administrador
        
        Map<String, Object> resultado = new HashMap<>();
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // Construcción dinámica de query vulnerable (API1:2023)
            StringBuilder query = new StringBuilder("INSERT INTO funcionarios (");
            StringBuilder values = new StringBuilder("VALUES (");
            
            for (String campo : datosFuncionario.keySet()) {
                query.append(campo).append(", ");
                values.append("'").append(datosFuncionario.get(campo)).append("', ");
            }
            
            // Remover última coma
            query.setLength(query.length() - 2);
            values.setLength(values.length() - 2);
            
            query.append(") ").append(values).append(")");
            
            Statement stmt = conn.createStatement();
            int filasAfectadas = stmt.executeUpdate(query.toString());
            
            resultado.put("mensaje", "Funcionario creado exitosamente");
            resultado.put("filas_afectadas", filasAfectadas);
            resultado.put("datos_insertados", datosFuncionario); // Exposición de todos los datos
            resultado.put("query_ejecutada", query.toString()); // Exposición de query
            
            conn.close();
            
        } catch (SQLException e) {
            resultado.put("error", "Error creando funcionario");
            resultado.put("error_detalle", e.getMessage());
            resultado.put("datos_intentados", datosFuncionario);
        }
        
        return resultado;
    }
    
    // Endpoint administrativo sin autenticación robusta (API5:2023)
    @GetMapping("/admin/todos")
    public Map<String, Object> listarTodosFuncionarios(@RequestParam(required = false) String admin_token) {
        
        // Validación de token débil (API2:2023)
        if (admin_token == null || !admin_token.equals(ADMIN_TOKEN)) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Token de administrador requerido");
            error.put("token_esperado", ADMIN_TOKEN); // Exposición del token válido
            return error;
        }
        
        // Sin rate limiting (API4:2023)
        // Un atacante podría extraer toda la base de datos
        
        Map<String, Object> resultado = new HashMap<>();
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // Consulta que expone todos los datos sensibles (API3:2023)
            String query = "SELECT * FROM funcionarios f " +
                          "LEFT JOIN evaluaciones e ON f.id = e.id_funcionario " +
                          "LEFT JOIN nomina n ON f.id = n.id_funcionario " +
                          "LEFT JOIN disciplinarios d ON f.id = d.id_funcionario";
            
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            List<Map<String, Object>> todosFuncionarios = new ArrayList<>();
            
            while (rs.next()) {
                Map<String, Object> funcionario = new HashMap<>();
                
                // Exposición masiva de datos (API3:2023)
                ResultSetMetaData metaData = rs.getMetaData();
                int columnCount = metaData.getColumnCount();
                
                for (int i = 1; i <= columnCount; i++) {
                    String columnName = metaData.getColumnName(i);
                    Object value = rs.getObject(i);
                    funcionario.put(columnName, value);
                }
                
                todosFuncionarios.add(funcionario);
            }
            
            resultado.put("total_funcionarios", todosFuncionarios.size());
            resultado.put("funcionarios_completos", todosFuncionarios);
            resultado.put("configuracion_sistema", Map.of(
                "servidor_bd", DB_URL,
                "usuario_bd", DB_USER,
                "version_java", System.getProperty("java.version"),
                "directorio_trabajo", System.getProperty("user.dir")
            ));
            
            conn.close();
            
        } catch (SQLException e) {
            resultado.put("error", "Error consultando funcionarios");
            resultado.put("error_sql_completo", e);
        }
        
        return resultado;
    }
    
    // Endpoint de actualización vulnerable (API1:2023 y API3:2023)
    @PutMapping("/actualizar/{cedula}")
    public Map<String, Object> actualizarFuncionario(@PathVariable String cedula,
                                                    @RequestBody Map<String, Object> nuevosDatos) {
        
        // Sin validación de autorización (API1:2023)
        // Un funcionario podría modificar datos de otros o escalarse privilegios
        
        Map<String, Object> resultado = new HashMap<>();
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            
            // Construcción dinámica vulnerable (API1:2023)
            StringBuilder query = new StringBuilder("UPDATE funcionarios SET ");
            
            for (String campo : nuevosDatos.keySet()) {
                query.append(campo).append(" = '").append(nuevosDatos.get(campo)).append("', ");
            }
            
            query.setLength(query.length() - 2); // Remover última coma
            query.append(" WHERE cedula = '").append(cedula).append("'");
            
            Statement stmt = conn.createStatement();
            int filasAfectadas = stmt.executeUpdate(query.toString());
            
            resultado.put("mensaje", "Funcionario actualizado");
            resultado.put("filas_afectadas", filasAfectadas);
            resultado.put("cambios_aplicados", nuevosDatos);
            resultado.put("query_ejecutada", query.toString());
            
            conn.close();
            
        } catch (SQLException e) {
            resultado.put("error", "Error actualizando funcionario");
            resultado.put("error_detalle", e.getMessage());
            resultado.put("cedula_objetivo", cedula);
            resultado.put("datos_intentados", nuevosDatos);
        }
        
        return resultado;
    }
}
''')
    
    # 5. Archivo de configuración del sistema (Muy común y crítico)
    with open(f"{test_dir}/config_sistema.properties", "w") as f:
        f.write('''# Configuración del Sistema - Alcaldía de Ibagué
# ARCHIVO CON MÚLTIPLES VULNERABILIDADES DE CONFIGURACIÓN (API8:2023)

# === CONFIGURACIÓN DE BASE DE DATOS ===
# Credenciales expuestas en texto plano
db.host=192.168.1.100
db.port=3306
db.name=alcaldia_ibague_prod
db.username=admin_alcaldia
db.password=AlcaldiaIbague2024!
db.root.password=SuperAdmin123!

# Cadenas de conexión con credenciales
db.connection.ciudadanos=mysql://admin:AlcaldiaIbague2024!@192.168.1.100:3306/ciudadanos
db.connection.predial=mysql://predial_user:Predial2024!@192.168.1.100:3306/sistema_predial
db.connection.nomina=mysql://rrhh_admin:RRHH_Pass2024@192.168.1.100:3306/nomina_funcionarios

# === CLAVES DE APIs EXTERNAS ===
# Claves de servicios gubernamentales
govco.api.key=GOVCO_ALCALDIA_IBAGUE_API_KEY_2024_SECRET
registraduria.api.key=REG_NACIONAL_API_12345678901234567890
dian.api.key=DIAN_TRIBUTARIA_SECRET_KEY_ALCALDIA_2024
icbf.api.key=ICBF_SOCIAL_API_SECRET_ALCALDIA

# Claves de servicios de pago
pse.merchant.id=ALCALDIA_IBAGUE_PSE_12345
pse.secret.key=PSE_SECRET_KEY_ALCALDIA_2024_PRODUCTION
credit.card.processor.key=CC_PROCESSOR_SECRET_12345678
bank.transfer.api.key=BANK_API_SECRET_ALCALDIA_IBAGUE

# Claves de servicios de notificación
email.smtp.password=EmailAlcaldia2024!
sms.gateway.key=SMS_GATEWAY_SECRET_ALCALDIA_2024
whatsapp.business.token=WHATSAPP_BUSINESS_API_TOKEN_SECRET

# === CONFIGURACIÓN DE SEGURIDAD ===
# Tokens y secretos de aplicación
jwt.secret.key=JWT_SECRET_ALCALDIA_IBAGUE_2024_SUPER_SECRET
encryption.aes.key=AES256_ENCRYPTION_KEY_ALCALDIA_2024
session.secret=SESSION_SECRET_ALCALDIA_IBAGUE_2024

# Configuraciones inseguras habilitadas
debug.mode=true
error.display.full=true
sql.debug.enabled=true
stack.trace.enabled=true

# === CONFIGURACIÓN DE USUARIOS ADMINISTRATIVOS ===
# Usuarios por defecto con contraseñas débiles
admin.default.username=admin
admin.default.password=admin123
admin.backup.username=alcaldia_admin
admin.backup.password=AlcaldiaAdmin2024

# Usuarios de sistema
system.user.db=db_admin
system.password.db=DbAdmin123!
system.user.ftp=ftp_alcaldia
system.password.ftp=FtpAlcaldia2024!

# === CONFIGURACIÓN DE SERVICIOS EXTERNOS ===
# URLs de servicios con credenciales embebidas
external.service.ciudadanos=https://admin:password123@servicios.gov.co/ciudadanos
external.service.predial=https://predial_user:predial_pass@catastro.gov.co/api
external.service.pagos=https://api_user:api_secret@pagos.gov.co/procesar

# === CONFIGURACIÓN DE INFRAESTRUCTURA ===
# Información sensible del servidor
server.internal.ip=192.168.1.50
server.admin.port=8080
server.debug.port=9999
server.ssh.port=22
server.ftp.port=21

# Rutas del sistema
system.backup.path=/var/backups/alcaldia/
system.logs.path=/var/log/alcaldia/
system.temp.path=/tmp/alcaldia/
system.uploads.path=/var/www/uploads/

# === CONFIGURACIÓN DE DESARROLLO ===
# Configuraciones que no deberían estar en producción
development.mode=true
test.data.enabled=true
mock.services.enabled=false
profiling.enabled=true

# Usuarios de prueba (¡En producción!)
test.user.admin=test_admin
test.password.admin=test123
test.user.funcionario=test_funcionario
test.password.funcionario=funcionario123

# === CONFIGURACIÓN DE LOGS ===
# Configuración que puede exponer información sensible
log.level=DEBUG
log.sql.queries=true
log.user.actions=true
log.sensitive.data=true
log.passwords=false
log.tokens=true

# === CONFIGURACIÓN DE CORS Y SEGURIDAD WEB ===
# Configuraciones inseguras
cors.allow.all.origins=true
cors.allow.credentials=true
csrf.protection.disabled=true
ssl.verification.disabled=true

# === INFORMACIÓN DEL SISTEMA ===
# Metadatos que podrían ser útiles para atacantes
system.version=AlcaldiaSystem v2.4.1
system.build.date=2024-09-15
system.environment=production
system.admin.email=admin@alcaldia-ibague.gov.co
system.support.phone=+57-8-2661000

# === CONFIGURACIÓN DE BACKUP ===
# Credenciales de sistemas de backup
backup.ftp.host=backup.alcaldia-ibague.gov.co
backup.ftp.username=backup_user
backup.ftp.password=BackupAlcaldia2024!
backup.cloud.access.key=CLOUD_BACKUP_ACCESS_KEY_SECRET
backup.cloud.secret.key=CLOUD_BACKUP_SECRET_KEY_2024

# === CONFIGURACIÓN DE MONITOREO ===
# Claves de servicios de monitoreo
monitoring.api.key=MONITORING_API_KEY_ALCALDIA_SECRET
analytics.tracking.id=GA-ALCALDIA-IBAGUE-2024
error.tracking.dsn=https://secret_key@sentry.io/alcaldia-project

# === NOTAS DE CONFIGURACIÓN ===
# IMPORTANTE: Este archivo contiene información sensible
# NO compartir fuera del equipo de desarrollo
# Cambiar contraseñas regularmente
# Última actualización: 2024-09-15 por admin_alcaldia
''')
    
    print(f"\n Casos de prueba específicos creados exitosamente:")
    print(f" {test_dir}/api_predial.php - API de consulta de impuesto predial")
    print(f" {test_dir}/api_certificados.py - API de expedición de certificados")
    print(f" {test_dir}/api_pagos_linea.js - API de pagos en línea")
    print(f" {test_dir}/sistema_funcionarios.java - Sistema de gestión de RRHH")
    print(f" {test_dir}/config_sistema.properties - Configuración del sistema")
    
    print(f"\n Vulnerabilidades incluidas por archivo:")
    print(f"   • API Predial: SQL Injection, BOLA, Exposición de datos, CORS inseguro")
    print(f"   • API Certificados: Rate limiting, SSRF, Escalación de privilegios, Path traversal")
    print(f"   • API Pagos: Datos de tarjetas expuestos, Sin límites, Configuración insegura")
    print(f"   • Sistema RRHH: Mass assignment, Exposición masiva de datos, Tokens débiles")
    print(f"   • Configuración: Credenciales hardcodeadas, Claves expuestas, Debug habilitado")
    
    print(f"\n Para probar el analizador:")
    print(f"   python3 analizador_seguridad.py --directorio {test_dir}")
    
    return test_dir

if __name__ == "__main__":
    crear_casos_alcaldia()
''')
    
    # 6. Script de validación final
    with open(f"{test_dir}/validar_sistema.py", "w") as f:
        f.write('''#!/usr/bin/env python3
"""
Script de Validación del Sistema Completo
Proyecto: Modelo de IA para Análisis de Vulnerabilidades
Estudiante: John Lugo - UNAD
"""

import subprocess
import sys
import os
import json
import time
from pathlib import Path

def verificar_ollama():
    """Verifica que Ollama esté funcionando"""
    print(" Verificando Ollama...")
    try:
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
        if result.returncode == 0:
            print(" Ollama está funcionando")
            if 'modeloseguridad' in result.stdout:
                print(" Modelo 'modeloseguridad' encontrado")
                return True
            else:
                print(" Modelo 'modeloseguridad' no encontrado")
                return False
        else:
            print(" Ollama no está funcionando")
            return False
    except FileNotFoundError:
        print(" Ollama no está instalado")
        return False

def verificar_analizador():
    """Verifica que el analizador esté disponible"""
    print(" Verificando analizador...")
    if os.path.exists('analizador_seguridad.py'):
        print(" Analizador encontrado")
        return True
    else:
        print(" Analizador no encontrado")
        return False

def ejecutar_pruebas():
    """Ejecuta las pruebas del sistema"""
    print(" Ejecutando pruebas del sistema...")
    
    # Crear casos de prueba
    print(" Creando casos de prueba...")
    try:
        subprocess.run([sys.executable, 'casos_prueba_alcaldia_especificos.py'], check=True)
        print(" Casos de prueba creados")
    except subprocess.CalledProcessError:
        print(" Error creando casos de prueba")
        return False
    
    # Ejecutar análisis
    print(" Ejecutando análisis...")
    try:
        result = subprocess.run([
            sys.executable, 'analizador_seguridad.py',
            '--directorio', 'casos_prueba_alcaldia',
            '--output', 'reporte_validacion.txt'
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(" Análisis completado exitosamente")
            return True
        else:
            print(f" Error en análisis: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(" Timeout en análisis")
        return False
    except subprocess.CalledProcessError as e:
        print(f" Error ejecutando análisis: {e}")
        return False

def verificar_resultados():
    """Verifica que los resultados sean correctos"""
    print(" Verificando resultados...")
    
    if os.path.exists('reporte_validacion.txt'):
        with open('reporte_validacion.txt', 'r', encoding='utf-8') as f:
            contenido = f.read()
        
        # Verificar que se encontraron vulnerabilidades
        if 'VULNERABILIDADES DETECTADAS' in contenido:
            print(" Se detectaron vulnerabilidades correctamente")
            
            # Contar vulnerabilidades por tipo
            vulnerabilidades_esperadas = [
                'API1:2023', 'API2:2023', 'API3:2023', 
                'API7:2023', 'API8:2023'
            ]
            
            encontradas = 0
            for vuln in vulnerabilidades_esperadas:
                if vuln in contenido:
                    encontradas += 1
            
            print(f" Encontradas {encontradas}/{len(vulnerabilidades_esperadas)} tipos de vulnerabilidades esperadas")
            
            if encontradas >= 3:
                print(" Validación de resultados exitosa")
                return True
            else:
                print(" Se encontraron pocas vulnerabilidades")
                return False
        else:
            print(" No se detectaron vulnerabilidades")
            return False
    else:
        print(" No se generó el reporte")
        return False

def generar_reporte_final():
    """Genera un reporte final de validación"""
    print(" Generando reporte final...")
    
    reporte = f"""
REPORTE DE VALIDACIÓN DEL SISTEMA
=================================
Fecha: {time.strftime('%Y-%m-%d %H:%M:%S')}
Proyecto: Modelo de IA para Análisis de Vulnerabilidades
Estudiante: John Lugo - UNAD

COMPONENTES VERIFICADOS:
 Ollama instalado y funcionando
 Modelo 'modeloseguridad' disponible
 Analizador de seguridad funcional
 Casos de prueba específicos para alcaldías
 Detección de vulnerabilidades OWASP Top 10

ARCHIVOS GENERADOS:
- casos_prueba_alcaldia/ (casos de prueba)
- reporte_validacion.txt (resultados del análisis)
- validacion_sistema.log (este reporte)

CONCLUSIÓN:
El sistema está completamente funcional y listo para ser usado
en el análisis de vulnerabilidades de las APIs de la Alcaldía de Ibagué.

PRÓXIMOS PASOS:
1. Ejecutar análisis en código real de la alcaldía
2. Revisar y corregir vulnerabilidades encontradas
3. Implementar monitoreo continuo
4. Capacitar al equipo técnico

CONTACTO:
John Freddy Lugo Luna - UNAD
Maestría en Ciberseguridad
"""
    
    with open('validacion_sistema.log', 'w', encoding='utf-8') as f:
        f.write(reporte)
    
    print(" Reporte final generado: validacion_sistema.log")

def main():
    """Función principal de validación"""
    print(" VALIDACIÓN DEL SISTEMA COMPLETO")
    print("=" * 50)
    
    # Lista de verificaciones
    verificaciones = [
        ("Ollama", verificar_ollama),
        ("Analizador", verificar_analizador),
        ("Pruebas", ejecutar_pruebas),
        ("Resultados", verificar_resultados)
    ]
    
    resultados = []
    
    for nombre, funcion in verificaciones:
        print(f"\n Verificando {nombre}...")
        resultado = funcion()
        resultados.append((nombre, resultado))
        
        if not resultado:
            print(f" Fallo en verificación de {nombre}")
            break
    
    # Resumen final
    print("\n" + "=" * 50)
    print(" RESUMEN DE VALIDACIÓN")
    print("=" * 50)
    
    exitosos = sum(1 for _, resultado in resultados if resultado)
    total = len(resultados)
    
    for nombre, resultado in resultados:
        estado = " EXITOSO" if resultado else " FALLIDO"
        print(f"{nombre}: {estado}")
    
    print(f"\nResultado: {exitosos}/{total} verificaciones exitosas")
    
    if exitosos == total:
        print("\n ¡SISTEMA COMPLETAMENTE VALIDADO!")
        print(" Tu modelo está listo para usar en producción")
        generar_reporte_final()
    else:
        print("\n Sistema parcialmente validado")
        print(" Revisa los errores anteriores y vuelve a ejecutar")
    
    return exitosos == total

if __name__ == "__main__":
    main()
''')
    
    print(f"\n Casos de prueba específicos para alcaldías creados exitosamente!")
    print(f" Directorio: {test_dir}")
    print(f" Archivos creados: 6")
    print(f"\n Para probar tu modelo:")
    print(f"   python3 analizador_seguridad.py --directorio {test_dir}")
    print(f"\n Para validar todo el sistema:")
    print(f"   python3 {test_dir}/validar_sistema.py")

if __name__ == "__main__":
    crear_casos_alcaldia()
