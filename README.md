Implementación y especialización de un modelo de inteligencia artificial para el análisis en tiempo real de vulnerabilidades en APIs desplegadas en la nube para la Alcaldía de Ibagué

Información académica


Autor	                  John Freddy Lugo Luna
Asesor	                Hernando José Peña Hidalgo
Institución	            Universidad Nacional Abierta y a Distancia – UNAD
Programa	              Maestría en Ciberseguridad
Escuela	                ECBTI – Escuela de Ciencias Básicas, Tecnología e Ingeniería
Ciudad	                Ibagué, Colombia
Año	                    2025

Descripción del proyecto

Implementar una solución basada en inteligencia artificial para el análisis en tiempo real de vulnerabilidades en APIs de la nube de la Alcaldía de Ibagué, mediante la adaptación de un modelo de lenguaje grande preentrenado e integración con políticas institucionales de seguridad de la información, con el propósito de fortalecer la protección de los servicios digitales y reducir el riesgo de ciberataques.

Objetivos

•	Identificar las principales amenazas y vulnerabilidades en APIs en la nube, a partir de la revisión de estándares (OWASP API Security Top 10), análisis de incidentes reales y buenas prácticas en plataformas de nube, para establecer la línea base de riesgos que oriente la especialización del modelo de IA.

•	Diseñar un sistema de inteligencia artificial aplicado a la detección automatizada de vulnerabilidades en APIs, mediante la adaptación de un modelo de lenguaje grande (LLM) pre-entrenado y su aplicación al análisis estático de código fuente, para optimizar la detección temprana de fallas y fortalecer la respuesta ante vulnerabilidades.

•	Proponer estrategias de mitigación y recomendaciones técnicas para desarrolladores y equipos de TI, basadas en los patrones identificados por el modelo de IA y las directrices del marco OWASP API Security Top 10, para reducir la exposición a riesgos y mejorar las prácticas de desarrollo seguro.

•	Construir una política institucional de seguridad de la información, alineada con la Política de Gobierno Digital y el Modelo Integrado de Planeación y Gestión (MIPG), para institucionalizar la gestión de riesgos en el uso de APIs y garantizar la sostenibilidad de las medidas de ciberseguridad. 


Contenido del repositorio

Archivo	                                                Descripción

AnexoA_analizador_seguridad.py	                        Script principal del analizador de seguridad basado en LLM
Anexo B_modelfile_seguridad	                            Modelfile de Ollama con la especialización en ciberseguridad
Anexo C_test_codigo_vulnerable.py	                      Casos de prueba con código vulnerable para validación
Anexo D_casos_prueba_alcaldia_especificos.py	          Casos de prueba específicos del contexto de la Alcaldía de Ibagué
Anexo E_guia_usuario_completa.docx	                    Guía de usuario completa del sistema
Anexo F_ws_20250923_080052.txt	                        Log de sesión de análisis – 23/09/2025
Anexo G_ws_20250924_075254.txt	                        Log de sesión de análisis – 24/09/2025
Anexo H_Politicas_Arquitecturas_Seguridad_APIs.docx	    Política de arquitectura de seguridad para APIs en la nube
Anexo I_Politicas_Configuracion_Segura_APIs.docx	      Política de configuración segura de APIs en la nube
Anexo J_systemd.txt	                                    Configuración del servicio systemd para despliegue continuo

Tecnologías utilizadas

•	Python 3.x
•	Ollama – Despliegue local de LLMs
•	OWASP API Security Top 10 – 2023
•	DevSecOps

Requisitos de instalación

Requisitos de instalación

1. Tener instalado Ollama (https://ollama.com/)
2. Clonar este repositorio:
   git clone https://github.com/johnlugoluna-hub/ai-api-security-analyzer.git
   cd ai-api-security-analyzer
3. Crear el modelo especializado:
   ollama create seguridad-api -f "Anexo B_modelfile_seguridad"
4. Ejecutar el analizador manualmente:
   python "Anexo A_analizador_seguridad.py"
5. (Opcional) Configurar el servicio de análisis automatizado con systemd:
   a. Copiar el archivo de servicio:
      sudo cp Anexo J_systemd.txt /etc/systemd/system/ollama-analisis.service
   b. Copiar el script bash de análisis:
      sudo cp analizar_ollama.sh /usr/local/bin/analizar_ollama.sh
      sudo chmod +x /usr/local/bin/analizar_ollama.sh
   c. Habilitar e iniciar el servicio:
      sudo systemctl daemon-reload
      sudo systemctl enable ollama-analisis
      sudo systemctl start ollama-analisis

Consulta Anexo E_guia_usuario_completa.docx y Anexo J_systemd.txt 
para instrucciones detalladas del despliegue continuo.

Licencia
Proyecto académico desarrollado para la Maestría en Ciberseguridad – UNAD.
Para uso investigativo y educativo.

