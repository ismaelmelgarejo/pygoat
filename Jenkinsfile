pipeline {
    agent any

    environment {
        DT_URL = 'http://dependecy-track-dtrack-apiserver-1:8084' 
        DD_URL = 'http://django-defectdojo-nginx-1:8080'
        DD_API_KEY = credentials('DEFECTDOJO_API_KEY')
        DT_API_KEY = credentials('DTRACK_API_KEY')
        DD_ENGAGEMENT_ID = '6'
        DOCKER_ARGS = '--rm --entrypoint="" --network devsecops-net -v /var/jenkins_home:/var/jenkins_home -w ${WORKSPACE}'
    }

    stages {
        stage('Limpieza') {
            steps { cleanWs() }
        }
        
        stage('Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/master']], 
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [[$class: 'CloneOption', depth: 0, noTags: false, reference: '', shallow: false]],
                    userRemoteConfigs: [[url: 'https://github.com/ismaelmelgarejo/pygoat.git']]
                ])
            }
        }

        stage('SAST - Bandit') {
            steps {
                script {
                    echo "--- Ejecutando Bandit ---"
                    // AGREGAMOS: -e PYTHONUNBUFFERED=1
                    // AGREGAMOS: --no-cache-dir al pip install
                    sh """
                        docker run ${DOCKER_ARGS} -e PYTHONUNBUFFERED=1 python:3.10-slim /bin/bash -c " \
                            pip install --no-cache-dir bandit && \
                            bandit -r . -f json -o bandit_report.json || true \
                        "
                    """
                }
            }
        }

        stage('Secrets - Gitleaks') {
            steps {
                script {
                    echo "--- Ejecutando Gitleaks (Como Root) ---"
                    // AGREGADO: -u root:root
                    // EXPLICACIÓN: --entrypoint /bin/sh sobreescribe el comando default
                    sh """
                        docker run ${DOCKER_ARGS} -u root:root --entrypoint /bin/sh zricethezav/gitleaks:v8.18.1 -c " \
                            git config --global --add safe.directory '*' && \
                            gitleaks detect -v --source . --log-opts='--all' --report-path gitleaks_report.json --exit-code 0 \
                        "
                    """
                }
            }
        }

        stage('SCA - Dependency Track (Puro & Robusto)') {
            steps {
                script {
                    def dtScript = """#!/bin/bash
                    set -e
                    echo "--- Instalando herramientas ---"
                    apt-get update -qq && apt-get install -y curl -qq
                    pip install cyclonedx-bom -q
                    
                    echo "--- Generando BOM (Inventario) ---"
                    cyclonedx-py requirements requirements.txt -o bom_inventory.json
                    
                    echo "--- Subiendo Inventario a DT ---"
                    curl -s -X POST "\$DT_URL/api/v1/bom" \
                        -H "Content-Type: multipart/form-data" \
                        -H "X-Api-Key: \$DT_API_KEY" \
                        -F "autoCreate=true" \
                        -F "projectName=Pygoat" \
                        -F "projectVersion=1.0" \
                        -F "bom=@bom_inventory.json"
                    
                    echo ""
                    echo "--- Esperando 60s a que DT analice... ---"
                    sleep 60
                    
                    echo "--- Obteniendo UUID ---"
                    curl -s -H "X-Api-Key: \$DT_API_KEY" "\$DT_URL/api/v1/project/lookup?name=Pygoat&version=1.0" > dt_project.json
                    
                    # Debug: Ver contenido del proyecto
                    cat dt_project.json
                    
                    PROJECT_UUID=\$(cat dt_project.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('uuid', ''))" 2>/dev/null)
                    
                    if [ -z "\$PROJECT_UUID" ]; then
                        echo "ERROR: No se pudo obtener UUID."
                        exit 1
                    fi
                    
                    echo "UUID Objetivo: \$PROJECT_UUID"
                    
                    echo "--- Descargando Findings (Con Reintentos) ---"
                    SUCCESS=0
                    
                    # Intentamos descargar hasta 5 veces
                    for i in 1 2 3 4 5; do
                        echo "Intento \$i de descarga..."
                        
                        # Capturamos codigo HTTP y contenido
                        HTTP_CODE=\$(curl -w "%{http_code}" -s -H "X-Api-Key: \$DT_API_KEY" \
                            "\$DT_URL/api/v1/finding/project/\$PROJECT_UUID?suppressed=false" \
                            -o dt_findings.json)
                        
                        echo "Codigo HTTP: \$HTTP_CODE"
                        
                        # Verificamos si es 200 OK
                        if [ "\$HTTP_CODE" == "200" ]; then
                            SIZE=\$(wc -c < dt_findings.json)
                            echo "Tamaño archivo: \$SIZE bytes"
                            
                            # Si tiene contenido, salimos
                            if [ "\$SIZE" -gt 2 ]; then
                                echo "¡Descarga Exitosa!"
                                SUCCESS=1
                                break
                            else
                                echo "Archivo vacio o [] (Sin hallazgos aun). Reintentando..."
                            fi
                        else
                            echo "Error en la API. Respuesta del servidor:"
                            cat dt_findings.json
                        fi
                        
                        sleep 10
                    done
                    
                    if [ \$SUCCESS -eq 0 ]; then
                        echo "ADVERTENCIA: No se pudieron descargar findings validos."
                        # Creamos un array vacio valido para que DefectDojo no falle con 400 Bad Request
                        echo '[]' > dt_findings.json
                    fi
                    
                    ls -lh dt_findings.json
                    """
                    
                    writeFile file: 'run_dt_pure.sh', text: dtScript
                    sh "chmod +x run_dt_pure.sh"
                    
                    sh """
                        docker run ${DOCKER_ARGS} \
                            -e DT_URL='${DT_URL}' \
                            -e DT_API_KEY='${DT_API_KEY}' \
                            python:3.10-slim /bin/bash ./run_dt_pure.sh
                    """
                }
            }
        }

        stage('Upload to DefectDojo') {
            steps {
                script {
                    echo "--- Subiendo Reportes ---"
                    sh "ls -lh bandit_report.json gitleaks_report.json dt_findings.json"
                    
                    sh """
                        docker run ${DOCKER_ARGS} curlimages/curl:latest /bin/sh -c " \
                            # 1. BANDIT
                            curl -v -X POST '${DD_URL}/api/v2/import-scan/' \
                                -H 'Authorization: Token ${DD_API_KEY}' \
                                -H 'Content-Type: multipart/form-data' \
                                -F 'active=true' \
                                -F 'verified=true' \
                                -F 'minimum_severity=High' \
                                -F 'close_old_findings=true' \
                                -F 'scan_type=Bandit Scan' \
                                -F 'engagement=${DD_ENGAGEMENT_ID}' \
                                -F 'file=@bandit_report.json' && \
                            
                            # 2. GITLEAKS
                            curl -v -X POST '${DD_URL}/api/v2/import-scan/' \
                                -H 'Authorization: Token ${DD_API_KEY}' \
                                -H 'Content-Type: multipart/form-data' \
                                -F 'active=true' \
                                -F 'verified=true' \
                                -F 'minimum_severity=High' \
                                -F 'close_old_findings=true' \
                                -F 'scan_type=Gitleaks Scan' \
                                -F 'engagement=${DD_ENGAGEMENT_ID}' \
                                -F 'file=@gitleaks_report.json' && \
                            
                            # 3. DT FINDINGS (FPF Export)
                            # Usamos el archivo puro descargado de la API
                            curl -v -X POST '${DD_URL}/api/v2/import-scan/' \
                                -H 'Authorization: Token ${DD_API_KEY}' \
                                -H 'Content-Type: multipart/form-data' \
                                -F 'active=true' \
                                -F 'verified=true' \
                                -F 'minimum_severity=High' \
                                -F 'close_old_findings=true' \
                                -F 'scan_type=Dependency Track Finding Packaging Format (FPF) Export' \
                                -F 'engagement=${DD_ENGAGEMENT_ID}' \
                                -F 'file=@dt_findings.json' \
                        "
                    """
                }
            }
        }
    }
}
