pipeline {
    agent any

    environment {
        // CORRECCIÓN: Verifica si tu contenedor se llama 'dependecy' o 'dependency'. Lo dejé como lo tenías.
        DT_URL = 'http://dependecy-track-dtrack-apiserver-1:8084' 
        DD_URL = 'http://django-defectdojo-nginx-1:8080'
        DD_API_KEY = credentials('DEFECTDOJO_API_KEY')
        DT_API_KEY = credentials('DTRACK_API_KEY')
        DD_ENGAGEMENT_ID = '6'
        // Mapeamos el workspace actual
        DOCKER_ARGS = '--rm --network devsecops-net -v /var/jenkins_home:/var/jenkins_home -w ${WORKSPACE}'
    }

    stages {
        // --- SOLUCIÓN DEL ERROR ---
        stage('Limpieza Forzada (Root)') {
            steps {
                script {
                    echo "--- Eliminando archivos bloqueados por Root ---"
                    // Usamos una imagen ligera (alpine) como root para borrar todo lo que hay en el workspace
                    // Esto soluciona el error "Operation not permitted"
                    sh """
                        docker run --rm -v ${WORKSPACE}:/workspace -w /workspace alpine sh -c 'rm -rf ./* || true'
                    """
                    // Ahora que está vacío, corremos cleanWs por si acaso para limpiar metadatos de Jenkins
                    cleanWs() 
                }
            }
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
                    // Nota: Al usar pip install, esto genera archivos root. La limpieza del inicio lo arreglará en el prox run.
                    sh """
                        docker run ${DOCKER_ARGS} python:3.10-slim /bin/bash -c " \
                            pip install bandit && \
                            bandit -r . -f json -o bandit_report.json || true \
                        "
                    """
                }
            }
        }

        stage('Secrets - Gitleaks') {
            steps {
                script {
                    echo "--- Ejecutando Gitleaks ---"
                    sh """
                        docker run ${DOCKER_ARGS} -u root:root zricethezav/gitleaks:v8.18.1 /bin/bash -c " \
                            git config --global --add safe.directory '*' && \
                            gitleaks detect -v --source . --log-opts='--all' --report-path gitleaks_report.json --exit-code 0 \
                        "
                    """
                }
            }
        }

        stage('SCA - Dependency Track') {
            steps {
                script {
                    // Creamos el script dentro del workspace
                    def dtScript = """#!/bin/bash
                    set -e
                    echo "--- [Container] Instalando dependencias ---"
                    apt-get update -qq && apt-get install -y curl -qq
                    pip install cyclonedx-bom -q
                    
                    echo "--- [Container] Generando BOM ---"
                    cyclonedx-py requirements requirements.txt -o bom_inventory.json
                    
                    echo "--- [Container] Subiendo a DT ---"
                    curl -s -X POST "\$DT_URL/api/v1/bom" \
                        -H "Content-Type: multipart/form-data" \
                        -H "X-Api-Key: \$DT_API_KEY" \
                        -F "autoCreate=true" \
                        -F "projectName=Pygoat" \
                        -F "projectVersion=1.0" \
                        -F "bom=@bom_inventory.json"
                    
                    echo ""
                    echo "--- Esperando 60s análisis... ---"
                    sleep 60
                    
                    echo "--- Obteniendo UUID ---"
                    curl -s -H "X-Api-Key: \$DT_API_KEY" "\$DT_URL/api/v1/project/lookup?name=Pygoat&version=1.0" > dt_project.json
                    
                    PROJECT_UUID=\$(cat dt_project.json | python3 -c "import sys, json; print(json.load(sys.stdin).get('uuid', ''))" 2>/dev/null)
                    
                    if [ -z "\$PROJECT_UUID" ]; then
                        echo "ERROR: No UUID found"
                        exit 1
                    fi
                    
                    echo "UUID: \$PROJECT_UUID"
                    
                    # Lógica de reintentos para descargar findings
                    SUCCESS=0
                    for i in 1 2 3 4 5; do
                        echo "Intento \$i..."
                        HTTP_CODE=\$(curl -w "%{http_code}" -s -H "X-Api-Key: \$DT_API_KEY" \
                            "\$DT_URL/api/v1/finding/project/\$PROJECT_UUID?suppressed=false" \
                            -o dt_findings.json)
                        
                        if [ "\$HTTP_CODE" == "200" ]; then
                            SIZE=\$(wc -c < dt_findings.json)
                            if [ "\$SIZE" -gt 2 ]; then
                                echo "Descarga OK."
                                SUCCESS=1
                                break
                            fi
                        fi
                        sleep 10
                    done
                    
                    if [ \$SUCCESS -eq 0 ]; then
                        echo '[]' > dt_findings.json
                    fi
                    """
                    
                    writeFile file: 'run_dt_pure.sh', text: dtScript
                    
                    // Ejecutamos el script DENTRO del contenedor
                    // OJO: No usamos 'chmod +x' desde fuera porque a veces falla si el archivo no es del usuario jenkins
                    // Lo ejecutamos pasando 'bash scriptname' directamente.
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
                    
                    sh """
                        docker run ${DOCKER_ARGS} curlimages/curl:latest /bin/sh -c " \
                            curl -s -X POST '${DD_URL}/api/v2/import-scan/' \
                                -H 'Authorization: Token ${DD_API_KEY}' \
                                -H 'Content-Type: multipart/form-data' \
                                -F 'active=true' \
                                -F 'verified=true' \
                                -F 'minimum_severity=High' \
                                -F 'close_old_findings=true' \
                                -F 'scan_type=Bandit Scan' \
                                -F 'engagement=${DD_ENGAGEMENT_ID}' \
                                -F 'file=@bandit_report.json' && \
                            
                            curl -s -X POST '${DD_URL}/api/v2/import-scan/' \
                                -H 'Authorization: Token ${DD_API_KEY}' \
                                -H 'Content-Type: multipart/form-data' \
                                -F 'active=true' \
                                -F 'verified=true' \
                                -F 'minimum_severity=High' \
                                -F 'close_old_findings=true' \
                                -F 'scan_type=Gitleaks Scan' \
                                -F 'engagement=${DD_ENGAGEMENT_ID}' \
                                -F 'file=@gitleaks_report.json' && \
                            
                            curl -s -X POST '${DD_URL}/api/v2/import-scan/' \
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
    
    // Bloque Post para asegurar limpieza o arreglar permisos para el futuro
    post {
        always {
            script {
                echo "--- Post-build: Arreglando permisos del workspace ---"
                // Opcional: Cambiar dueño de los archivos de vuelta a 1000:1000 (jenkins)
                // para que jenkins pueda leerlos en la interfaz o borrarlos normalmente.
                sh "docker run --rm -v ${WORKSPACE}:/workspace alpine chown -R 1000:1000 /workspace || true"
            }
        }
    }
}