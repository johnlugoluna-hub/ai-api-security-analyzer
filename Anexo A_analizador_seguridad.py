#!/usr/bin/env python3
"""
Analizador de Seguridad para APIs - OWASP Top 10
Proyecto de Maestría - John Lugo - UNAD
Análisis automatizado de vulnerabilidades en código fuente usando Ollama
"""

import os
import sys
import json
import requests
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import re
from dataclasses import dataclass, asdict

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('analizador_seguridad.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Vulnerabilidad:
    """Estructura de datos para una vulnerabilidad encontrada"""
    archivo: str
    vulnerabilidad: str
    linea: int
    cvss: float
    evidencia: str
    descripcion: str
    recomendaciones: str
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

class OllamaClient:
    """Cliente para interactuar con el servicio Ollama"""
    
    def __init__(self, host: str = "localhost", port: int = 11434, model: str = "modeloseguridad"):
        self.base_url = f"http://{host}:{port}"
        self.model = model
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        
    def verificar_conexion(self) -> bool:
        """Verifica que el servicio Ollama esté disponible"""
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=10)
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.error(f"Error conectando con Ollama: {e}")
            return False
    
    def verificar_modelo(self) -> bool:
        """Verifica que el modelo esté disponible"""
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return any(model['name'].startswith(self.model) for model in models)
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error verificando modelo: {e}")
            return False
    
    def analizar_codigo(self, codigo: str, nombre_archivo: str) -> str:
        """Envía código al modelo para análisis de vulnerabilidades"""
        prompt = f"""Analiza el siguiente código del archivo '{nombre_archivo}' en busca de vulnerabilidades de seguridad según OWASP API Security Top 10 2023:

```
{codigo}
```

Proporciona el análisis en el formato especificado."""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "top_k": 40,
                "top_p": 0.9
            }
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/generate",
                data=json.dumps(payload),
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "")
            else:
                logger.error(f"Error en respuesta de Ollama: {response.status_code}")
                return ""
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error enviando código a Ollama: {e}")
            return ""

class AnalizadorCodigo:
    """Analizador principal de código fuente"""
    
    # Extensiones de archivo soportadas
    EXTENSIONES_SOPORTADAS = {
        '.py': 'python',
        '.php': 'php',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.java': 'java',
        '.cs': 'csharp',
        '.cpp': 'cpp',
        '.c': 'c',
        '.go': 'go',
        '.rb': 'ruby',
        '.rs': 'rust',
        '.sql': 'sql',
        '.json': 'json',
        '.xml': 'xml',
        '.yaml': 'yaml',
        '.yml': 'yaml'
    }
    
    # Archivos y directorios a ignorar
    IGNORAR = {
        'node_modules', '.git', '.svn', '__pycache__', '.pytest_cache',
        'vendor', 'build', 'dist', '.vscode', '.idea', 'target',
        '.DS_Store', 'Thumbs.db'
    }
    
    def __init__(self, ollama_client: OllamaClient):
        self.ollama = ollama_client
        self.vulnerabilidades: List[Vulnerabilidad] = []
        self.archivos_procesados = 0
        self.archivos_con_vulnerabilidades = 0
        
    def es_archivo_codigo(self, ruta: Path) -> bool:
        """Determina si un archivo es código fuente analizable"""
        return ruta.suffix.lower() in self.EXTENSIONES_SOPORTADAS
    
    def debe_ignorar(self, ruta: Path) -> bool:
        """Determina si una ruta debe ser ignorada"""
        partes = ruta.parts
        return any(parte in self.IGNORAR for parte in partes)
    
    def leer_archivo(self, ruta: Path) -> Optional[str]:
        """Lee el contenido de un archivo de código"""
        try:
            # Intentar diferentes codificaciones
            codificaciones = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            
            for codificacion in codificaciones:
                try:
                    with open(ruta, 'r', encoding=codificacion) as archivo:
                        contenido = archivo.read()
                        # Verificar que el contenido sea válido
                        if len(contenido.strip()) > 0:
                            return contenido
                except UnicodeDecodeError:
                    continue
                    
            logger.warning(f"No se pudo leer el archivo {ruta} con ninguna codificación")
            return None
            
        except Exception as e:
            logger.error(f"Error leyendo archivo {ruta}: {e}")
            return None
    
    def parsear_respuesta_ollama(self, respuesta: str, nombre_archivo: str) -> List[Vulnerabilidad]:
        """Parsea la respuesta del modelo y extrae vulnerabilidades"""
        vulnerabilidades = []
        
        if not respuesta or "NO SE ENCONTRARON VULNERABILIDADES" in respuesta.upper():
            return vulnerabilidades
        
        # Patrones para extraer información estructurada
        patron_vulnerabilidad = re.compile(
            r'\*\*ARCHIVO:\*\*\s*(.+?)\n'
            r'\*\*VULNERABILIDAD:\*\*\s*(.+?)\n'
            r'\*\*LÍNEA:\*\*\s*(\d+)\n'
            r'\*\*CVSS:\*\*\s*([\d.]+)\n'
            r'\*\*EVIDENCIA:\*\*\s*(.+?)\n'
            r'\*\*DESCRIPCIÓN:\*\*\s*(.+?)\n'
            r'\*\*RECOMENDACIONES:\*\*\s*(.+?)(?=\n\*\*ARCHIVO:\*\*|\n\n|\Z)',
            re.DOTALL | re.IGNORECASE
        )
        
        matches = patron_vulnerabilidad.findall(respuesta)
        
        for match in matches:
            try:
                vulnerabilidad = Vulnerabilidad(
                    archivo=match[0].strip(),
                    vulnerabilidad=match[1].strip(),
                    linea=int(match[2].strip()),
                    cvss=float(match[3].strip()),
                    evidencia=match[4].strip(),
                    descripcion=match[5].strip(),
                    recomendaciones=match[6].strip()
                )
                vulnerabilidades.append(vulnerabilidad)
                
            except (ValueError, IndexError) as e:
                logger.warning(f"Error parseando vulnerabilidad en {nombre_archivo}: {e}")
                continue
        
        # Si no se encontraron matches con el patrón estructurado,
        # intentar extraer información de forma más flexible
        if not vulnerabilidades and respuesta.strip():
            # Buscar indicadores de vulnerabilidades
            indicadores = [
                "API1:2023", "API2:2023", "API3:2023", "API4:2023", "API5:2023",
                "API6:2023", "API7:2023", "API8:2023", "API9:2023", "API10:2023",
                "BOLA", "Authentication", "Authorization", "SSRF", "Injection"
            ]
            
            if any(indicador in respuesta for indicador in indicadores):
                # Crear vulnerabilidad genérica si se detectan indicadores
                vulnerabilidad = Vulnerabilidad(
                    archivo=nombre_archivo,
                    vulnerabilidad="Vulnerabilidad detectada (formato no estructurado)",
                    linea=1,
                    cvss=5.0,
                    evidencia=respuesta[:200] + "..." if len(respuesta) > 200 else respuesta,
                    descripcion="El modelo detectó posibles vulnerabilidades pero no pudo estructurar la respuesta",
                    recomendaciones="Revisar manualmente el análisis completo y aplicar correcciones según OWASP"
                )
                vulnerabilidades.append(vulnerabilidad)
        
        return vulnerabilidades
    
    def analizar_archivo(self, ruta: Path) -> List[Vulnerabilidad]:
        """Analiza un archivo individual"""
        logger.info(f"Analizando archivo: {ruta}")
        
        contenido = self.leer_archivo(ruta)
        if not contenido:
            return []
        
        # Limitar tamaño del archivo para evitar problemas de memoria
        if len(contenido) > 50000:  # 50KB límite
            logger.warning(f"Archivo {ruta} muy grande, analizando primeros 50KB")
            contenido = contenido[:50000]
        
        respuesta = self.ollama.analizar_codigo(contenido, str(ruta))
        if not respuesta:
            logger.warning(f"No se obtuvo respuesta del modelo para {ruta}")
            return []
        
        vulnerabilidades = self.parsear_respuesta_ollama(respuesta, str(ruta))
        
        if vulnerabilidades:
            logger.info(f"Encontradas {len(vulnerabilidades)} vulnerabilidades en {ruta}")
            self.archivos_con_vulnerabilidades += 1
        
        return vulnerabilidades
    
    def recorrer_directorio(self, directorio: Path) -> List[Path]:
        """Recorre recursivamente un directorio y encuentra archivos de código"""
        archivos_codigo = []
        
        try:
            for ruta in directorio.rglob('*'):
                if ruta.is_file() and self.es_archivo_codigo(ruta) and not self.debe_ignorar(ruta):
                    archivos_codigo.append(ruta)
                    
        except PermissionError as e:
            logger.error(f"Sin permisos para acceder a {directorio}: {e}")
        except Exception as e:
            logger.error(f"Error recorriendo directorio {directorio}: {e}")
            
        return archivos_codigo
    
    def analizar_directorio(self, directorio: str) -> List[Vulnerabilidad]:
        """Analiza todos los archivos de código en un directorio"""
        directorio_path = Path(directorio)
        
        if not directorio_path.exists():
            logger.error(f"El directorio {directorio} no existe")
            return []
        
        if not directorio_path.is_dir():
            logger.error(f"{directorio} no es un directorio")
            return []
        
        logger.info(f"Iniciando análisis del directorio: {directorio}")
        
        archivos = self.recorrer_directorio(directorio_path)
        logger.info(f"Encontrados {len(archivos)} archivos de código para analizar")
        
        todas_vulnerabilidades = []
        
        for archivo in archivos:
            try:
                vulnerabilidades = self.analizar_archivo(archivo)
                todas_vulnerabilidades.extend(vulnerabilidades)
                self.archivos_procesados += 1
                
                # Mostrar progreso cada 10 archivos
                if self.archivos_procesados % 10 == 0:
                    logger.info(f"Progreso: {self.archivos_procesados}/{len(archivos)} archivos procesados")
                    
            except Exception as e:
                logger.error(f"Error analizando archivo {archivo}: {e}")
                continue
        
        self.vulnerabilidades.extend(todas_vulnerabilidades)
        return todas_vulnerabilidades

class GeneradorReportes:
    """Generador de reportes de vulnerabilidades"""
    
    def __init__(self, vulnerabilidades: List[Vulnerabilidad]):
        self.vulnerabilidades = vulnerabilidades
    
    def generar_reporte_txt(self, archivo_salida: str) -> None:
        """Genera reporte en formato texto plano"""
        with open(archivo_salida, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("REPORTE DE ANÁLISIS DE VULNERABILIDADES - OWASP API TOP 10\n")
            f.write("Proyecto: Análisis de APIs Alcaldía de Ibagué\n")
            f.write("Autor: John Lugo - UNAD\n")
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"RESUMEN EJECUTIVO\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total de vulnerabilidades encontradas: {len(self.vulnerabilidades)}\n")
            
            # Estadísticas por tipo
            tipos = {}
            cvss_criticas = 0
            cvss_altas = 0
            cvss_medias = 0
            cvss_bajas = 0
            
            for vuln in self.vulnerabilidades:
                tipo = vuln.vulnerabilidad.split(' - ')[0] if ' - ' in vuln.vulnerabilidad else vuln.vulnerabilidad
                tipos[tipo] = tipos.get(tipo, 0) + 1
                
                if vuln.cvss >= 9.0:
                    cvss_criticas += 1
                elif vuln.cvss >= 7.0:
                    cvss_altas += 1
                elif vuln.cvss >= 4.0:
                    cvss_medias += 1
                else:
                    cvss_bajas += 1
            
            f.write(f"Vulnerabilidades críticas (CVSS 9.0-10.0): {cvss_criticas}\n")
            f.write(f"Vulnerabilidades altas (CVSS 7.0-8.9): {cvss_altas}\n")
            f.write(f"Vulnerabilidades medias (CVSS 4.0-6.9): {cvss_medias}\n")
            f.write(f"Vulnerabilidades bajas (CVSS 0.1-3.9): {cvss_bajas}\n\n")
            
            f.write("DISTRIBUCIÓN POR TIPO DE VULNERABILIDAD\n")
            f.write("-" * 40 + "\n")
            for tipo, cantidad in sorted(tipos.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{tipo}: {cantidad}\n")
            f.write("\n")
            
            f.write("DETALLE DE VULNERABILIDADES\n")
            f.write("=" * 80 + "\n\n")
            
            # Ordenar por CVSS descendente
            vulnerabilidades_ordenadas = sorted(self.vulnerabilidades, key=lambda x: x.cvss, reverse=True)
            
            for i, vuln in enumerate(vulnerabilidades_ordenadas, 1):
                f.write(f"VULNERABILIDAD #{i}\n")
                f.write("-" * 40 + "\n")
                f.write(f"ARCHIVO: {vuln.archivo}\n")
                f.write(f"TIPO: {vuln.vulnerabilidad}\n")
                f.write(f"LÍNEA: {vuln.linea}\n")
                f.write(f"CVSS: {vuln.cvss}\n")
                f.write(f"EVIDENCIA:\n{vuln.evidencia}\n\n")
                f.write(f"DESCRIPCIÓN:\n{vuln.descripcion}\n\n")
                f.write(f"RECOMENDACIONES:\n{vuln.recomendaciones}\n\n")
                f.write("=" * 80 + "\n\n")
    
    def generar_reporte_json(self, archivo_salida: str) -> None:
        """Genera reporte en formato JSON"""
        reporte = {
            "metadata": {
                "proyecto": "Análisis de APIs Alcaldía de Ibagué",
                "autor": "John Lugo - UNAD",
                "fecha": datetime.now().isoformat(),
                "total_vulnerabilidades": len(self.vulnerabilidades)
            },
            "estadisticas": self._generar_estadisticas(),
            "vulnerabilidades": [asdict(vuln) for vuln in self.vulnerabilidades]
        }
        
        with open(archivo_salida, 'w', encoding='utf-8') as f:
            json.dump(reporte, f, indent=2, ensure_ascii=False)
    
    def generar_reporte_csv(self, archivo_salida: str) -> None:
        """Genera reporte en formato CSV"""
        import csv
        
        with open(archivo_salida, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Archivo', 'Vulnerabilidad', 'Línea', 'CVSS', 
                'Evidencia', 'Descripción', 'Recomendaciones', 'Timestamp'
            ])
            
            for vuln in self.vulnerabilidades:
                writer.writerow([
                    vuln.archivo, vuln.vulnerabilidad, vuln.linea, vuln.cvss,
                    vuln.evidencia, vuln.descripcion, vuln.recomendaciones, vuln.timestamp
                ])
    
    def _generar_estadisticas(self) -> Dict:
        """Genera estadísticas del análisis"""
        if not self.vulnerabilidades:
            return {}
        
        tipos = {}
        cvss_stats = {"criticas": 0, "altas": 0, "medias": 0, "bajas": 0}
        archivos_afectados = set()
        
        for vuln in self.vulnerabilidades:
            # Contar tipos
            tipo = vuln.vulnerabilidad.split(' - ')[0] if ' - ' in vuln.vulnerabilidad else vuln.vulnerabilidad
            tipos[tipo] = tipos.get(tipo, 0) + 1
            
            # Contar por severidad CVSS
            if vuln.cvss >= 9.0:
                cvss_stats["criticas"] += 1
            elif vuln.cvss >= 7.0:
                cvss_stats["altas"] += 1
            elif vuln.cvss >= 4.0:
                cvss_stats["medias"] += 1
            else:
                cvss_stats["bajas"] += 1
            
            # Archivos afectados
            archivos_afectados.add(vuln.archivo)
        
        return {
            "por_tipo": tipos,
            "por_severidad": cvss_stats,
            "archivos_afectados": len(archivos_afectados),
            "cvss_promedio": sum(v.cvss for v in self.vulnerabilidades) / len(self.vulnerabilidades)
        }

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description="Analizador de Seguridad para APIs - OWASP Top 10",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python analizador_seguridad.py /ruta/al/codigo
  python analizador_seguridad.py /ruta/al/codigo --host 192.168.1.100 --port 11434
  python analizador_seguridad.py /ruta/al/codigo --modelo mi_modelo_personalizado
  python analizador_seguridad.py /ruta/al/codigo --formato json --salida reporte.json
        """
    )
    
    parser.add_argument(
        'directorio',
        help='Directorio con código fuente a analizar'
    )
    
    parser.add_argument(
        '--host',
        default='localhost',
        help='Host del servicio Ollama (default: localhost)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=11434,
        help='Puerto del servicio Ollama (default: 11434)'
    )
    
    parser.add_argument(
        '--modelo',
        default='modeloseguridad',
        help='Nombre del modelo Ollama a usar (default: modeloseguridad)'
    )
    
    parser.add_argument(
        '--formato',
        choices=['txt', 'json', 'csv', 'todos'],
        default='txt',
        help='Formato del reporte de salida (default: txt)'
    )
    
    parser.add_argument(
        '--salida',
        help='Archivo de salida (default: reporte_vulnerabilidades_TIMESTAMP)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Mostrar información detallada durante el análisis'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Inicializar cliente Ollama
    logger.info("Inicializando cliente Ollama...")
    ollama_client = OllamaClient(args.host, args.port, args.modelo)
    
    # Verificar conexión
    if not ollama_client.verificar_conexion():
        logger.error("No se puede conectar con el servicio Ollama")
        logger.error(f"Verifique que Ollama esté ejecutándose en {args.host}:{args.port}")
        sys.exit(1)
    
    # Verificar modelo
    if not ollama_client.verificar_modelo():
        logger.error(f"El modelo '{args.modelo}' no está disponible")
        logger.error("Modelos disponibles:")
        try:
            response = ollama_client.session.get(f"{ollama_client.base_url}/api/tags")
            if response.status_code == 200:
                models = response.json().get('models', [])
                for model in models:
                    logger.error(f"  - {model['name']}")
        except:
            pass
        sys.exit(1)
    
    logger.info(f"Conexión establecida con Ollama usando modelo: {args.modelo}")
    
    # Inicializar analizador
    analizador = AnalizadorCodigo(ollama_client)
    
    # Realizar análisis
    inicio = datetime.now()
    vulnerabilidades = analizador.analizar_directorio(args.directorio)
    fin = datetime.now()
    
    # Mostrar resumen
    logger.info("=" * 60)
    logger.info("ANÁLISIS COMPLETADO")
    logger.info("=" * 60)
    logger.info(f"Tiempo total: {fin - inicio}")
    logger.info(f"Archivos procesados: {analizador.archivos_procesados}")
    logger.info(f"Archivos con vulnerabilidades: {analizador.archivos_con_vulnerabilidades}")
    logger.info(f"Total vulnerabilidades encontradas: {len(vulnerabilidades)}")
    
    if vulnerabilidades:
        # Generar reportes
        generador = GeneradorReportes(vulnerabilidades)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if args.salida:
            base_nombre = args.salida.rsplit('.', 1)[0]
        else:
            base_nombre = f"reporte_vulnerabilidades_{timestamp}"
        
        if args.formato == 'txt' or args.formato == 'todos':
            archivo_txt = f"{base_nombre}.txt"
            generador.generar_reporte_txt(archivo_txt)
            logger.info(f"Reporte TXT generado: {archivo_txt}")
        
        if args.formato == 'json' or args.formato == 'todos':
            archivo_json = f"{base_nombre}.json"
            generador.generar_reporte_json(archivo_json)
            logger.info(f"Reporte JSON generado: {archivo_json}")
        
        if args.formato == 'csv' or args.formato == 'todos':
            archivo_csv = f"{base_nombre}.csv"
            generador.generar_reporte_csv(archivo_csv)
            logger.info(f"Reporte CSV generado: {archivo_csv}")
        
        # Mostrar estadísticas rápidas
        criticas = sum(1 for v in vulnerabilidades if v.cvss >= 9.0)
        altas = sum(1 for v in vulnerabilidades if 7.0 <= v.cvss < 9.0)
        
        if criticas > 0:
            logger.warning(f"¡ATENCIÓN! Se encontraron {criticas} vulnerabilidades CRÍTICAS")
        if altas > 0:
            logger.warning(f"Se encontraron {altas} vulnerabilidades de severidad ALTA")
            
    else:
        logger.info("No se encontraron vulnerabilidades en el código analizado")
    
    logger.info("Análisis finalizado exitosamente")

if __name__ == "__main__":
    main()

