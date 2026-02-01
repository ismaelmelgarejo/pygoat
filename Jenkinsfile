pipeline {
  agent {
   docker {
      image 'python:3.11-slim'
      args '-u root'
    }
  }
  options {
    timestamps()
    skipDefaultCheckout(true)
  }
  stages {
    stage('Init Workspace') {
      steps {
        deleteDir()
      }
    }

  environment {
    // ====== URLs (TU SETUP) ======
    // Dependency-Track API Server expuesto en tu host:8082
    DTRACK_URL     = "http://172.17.0.1:8084"

    // DefectDojo expuesto en tu host:8086 (según docker ps)
    DEFECTDOJO_URL = "http://172.17.0.1:8080"

    // ====== Nombres para el ejercicio ======
    PRODUCT_NAME     = "PyGoat"
    DTRACK_VERSION   = "1.0"
    ENGAGEMENT_NAME  = "CI/CD Security Pipeline"
    SBOM_SCAN_TYPE   = "CycloneDX Scan"

    // ====== GATES ======
    // true = falla el build si hay HIGH/CRITICAL
    // false = continúa para probar DefectDojo (marca UNSTABLE)
    ENFORCE_GATES = "false"

    // Umbrales (ajustables)
    BANDIT_MAX_HIGH   = "0"
    DTRACK_MAX_HIGH   = "0"
    DTRACK_MAX_CRIT   = "0"
  }

  stages {

    stage('Setup Tools') {
      steps {
        sh '''
          set -euo pipefail
          apt-get update -y
          apt-get install -y --no-install-recommends \
            curl jq git wget ca-certificates tar coreutils
          update-ca-certificates >/dev/null 2>&1 || true
        '''
      }
    }

    stage('Checkout Repo') {
      steps {
        sh '''
          set -euo pipefail
          rm -rf src
          git clone https://github.com/ismaelmelgarejo/pygoat.git src
        '''
      }
    }

    stage('SAST - Bandit') {
      steps {
        sh '''
          set -euo pipefail
          cd src
          pip install --upgrade pip >/dev/null
          pip install bandit >/dev/null

          bandit -r . -f json -o bandit-report.json || true
          test -s bandit-report.json || echo '{"results":[],"errors":[]}' > bandit-report.json
        '''
      }
    }

    stage('SCA - SBOM CycloneDX (JSON preferido, fallback XML)') {
      steps {
        sh '''
          set -euo pipefail
          cd src
          pip install cyclonedx-bom >/dev/null

          REQ="$(find . -maxdepth 3 -name "requirements*.txt" -print -quit || true)"
          if [ -z "${REQ:-}" ]; then
            echo "ERROR: No se encontró requirements*.txt"
            exit 1
          fi

          rm -f sbom.json sbom.xml

          # Intento JSON
          set +e
          cyclonedx-py requirements -i "$REQ" -o sbom.json
          RC=$?
          set -e

          if [ $RC -eq 0 ] && [ -s sbom.json ] && head -c 1 sbom.json | grep -Eq '[\\{\\[]'; then
            echo "[OK] SBOM en JSON: sbom.json"
          else
            echo "[!] JSON no disponible; intento XML..."
            rm -f sbom.json
            cyclonedx-py requirements -i "$REQ" -o sbom.xml

            if [ ! -s sbom.xml ] || ! head -c 1 sbom.xml | grep -q "<"; then
              echo "ERROR: SBOM inválido (ni JSON ni XML). Primeras líneas:"
              head -n 30 sbom.xml || true
              exit 1
            fi
            echo "[OK] SBOM en XML: sbom.xml"
          fi
        '''
      }
    }

    stage('Secret Scanning - Gitleaks') {
      steps {
        sh '''
          set -euo pipefail
          cd src

          if ! command -v gitleaks >/dev/null 2>&1; then
            wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz
            tar -xzf gitleaks_8.18.4_linux_x64.tar.gz
            mv gitleaks /usr/local/bin/gitleaks
            chmod +x /usr/local/bin/gitleaks
          fi

          gitleaks detect --source . --report-format json --report-path gitleaks-report.json || true
          test -s gitleaks-report.json || echo "[]" > gitleaks-report.json
        '''
      }
    }

    stage('Upload SBOM to Dependency-Track') {
      steps {
        withCredentials([string(credentialsId: 'DTRACK_API_KEY', variable: 'DTRACK_KEY')]) {
          sh '''
            set -euo pipefail
            cd src

            # Elegir SBOM final (json o xml)
            if [ -s sbom.json ]; then
              SBOM_FILE="sbom.json"
            else
              SBOM_FILE="sbom.xml"
            fi
            echo "[*] Usando SBOM_FILE=$SBOM_FILE"

            # Healthcheck del API
            curl -sfL "$DTRACK_URL/api/openapi.json" >/dev/null
            curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Accept: application/json" \
              "$DTRACK_URL/api/version" >/dev/null

            # Lookup por nombre+version (este endpoint es el que te funcionó)
            LOOKUP_JSON="$(curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Accept: application/json" \
              "$DTRACK_URL/api/v1/project/lookup?name=$PRODUCT_NAME&version=$DTRACK_VERSION" || true)"

            if echo "$LOOKUP_JSON" | jq -e '.uuid' >/dev/null 2>&1; then
              PROJECT_UUID="$(echo "$LOOKUP_JSON" | jq -r '.uuid')"
              echo "[*] Proyecto ya existe: $PROJECT_UUID"
            else
              echo "[*] Proyecto no existe; creando..."
              curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Content-Type: application/json" \
                -d "{\"name\":\"$PRODUCT_NAME\",\"version\":\"$DTRACK_VERSION\",\"description\":\"Proyecto PyGoat en pipeline CI/CD\",\"classifier\":\"APPLICATION\"}" \
                "$DTRACK_URL/api/v1/project" >/dev/null

              PROJECT_UUID="$(curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Accept: application/json" \
                "$DTRACK_URL/api/v1/project/lookup?name=$PRODUCT_NAME&version=$DTRACK_VERSION" | jq -r '.uuid')"
            fi

            test -n "$PROJECT_UUID"
            echo "[*] PROJECT_UUID=$PROJECT_UUID"
            echo "$PROJECT_UUID" > ../dtrack_project_uuid.txt

            # Upload BOM (multipart) -> endpoint que ya te devolvió HTTP 200
            HTTP_CODE="$(curl -s -o /dev/null -w "%{http_code}" \
              -H "X-Api-Key: $DTRACK_KEY" \
              -F "project=$PROJECT_UUID" \
              -F "bom=@$SBOM_FILE" \
              "$DTRACK_URL/api/v1/bom")"

            echo "[*] Upload BOM HTTP: $HTTP_CODE"
            if [ "$HTTP_CODE" -lt 200 ] || [ "$HTTP_CODE" -ge 300 ]; then
              echo "ERROR: Upload BOM falló con HTTP $HTTP_CODE"
              exit 1
            fi

            echo "[OK] SBOM subida a Dependency-Track"
          '''
        }
      }
    }

    stage('Security Gate (Bandit + Dependency-Track)') {
      steps {
        withCredentials([string(credentialsId: 'DTRACK_API_KEY', variable: 'DTRACK_KEY')]) {
          script {
            // Hacemos el gate en shell y luego decidimos si fallar o marcar UNSTABLE
            def rc = sh(script: '''
              set -euo pipefail
              cd pygoat

              # --- Bandit gate (HIGH) ---
              B_HIGH="$(jq '[.results[] | select(.issue_severity=="HIGH")] | length' bandit-report.json)"
              B_MED="$(jq '[.results[] | select(.issue_severity=="MEDIUM")] | length' bandit-report.json)"
              echo "[Bandit] HIGH=$B_HIGH MEDIUM=$B_MED"

              # --- DTrack gate (HIGH/CRITICAL) ---
              sleep 20
              PROJECT_UUID="$(cat ../dtrack_project_uuid.txt)"
              test -n "$PROJECT_UUID"

              VULNS="$(curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Accept: application/json" \
                "$DTRACK_URL/api/v1/vulnerability/project/$PROJECT_UUID" || echo '[]')"

              D_HIGH="$(echo "$VULNS" | jq '[.[] | select(.severity=="HIGH")] | length')"
              D_CRIT="$(echo "$VULNS" | jq '[.[] | select(.severity=="CRITICAL")] | length')"
              echo "[Dependency-Track] HIGH=$D_HIGH CRITICAL=$D_CRIT"

              # resumen para post
              {
                echo "BANDIT_HIGH=$B_HIGH"
                echo "DTRACK_HIGH=$D_HIGH"
                echo "DTRACK_CRITICAL=$D_CRIT"
              } > ../gate_summary.txt

              FAIL=0
              if [ "$B_HIGH" -gt "${BANDIT_MAX_HIGH}" ]; then FAIL=1; fi
              if [ "$D_HIGH" -gt "${DTRACK_MAX_HIGH}" ]; then FAIL=1; fi
              if [ "$D_CRIT" -gt "${DTRACK_MAX_CRIT}" ]; then FAIL=1; fi

              if [ "$FAIL" -eq 1 ]; then
                echo "GATE_FAILED=1" >> ../gate_summary.txt
                exit 3
              else
                echo "GATE_FAILED=0" >> ../gate_summary.txt
              fi
            ''', returnStatus: true)

            def summary = readFile('gate_summary.txt')
            echo "Gate summary:\n${summary}"

            if (rc != 0) {
              if (env.ENFORCE_GATES?.toBoolean()) {
                error("Security Gate FAILED (ENFORCE_GATES=true)")
              } else {
                echo "ENFORCE_GATES=false → Continúo para probar integración con DefectDojo (marco UNSTABLE)."
                currentBuild.result = 'UNSTABLE'
              }
            }
          }
        }
      }
    }

    stage('Upload to DefectDojo (Bandit + CycloneDX + Gitleaks)') {
      steps {
        withCredentials([string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY')]) {
          sh '''
            set -euo pipefail
            cd pygoat

            AUTH="Authorization: Token ${DD_API_KEY}"

            # IMPORTANTE:
            # Tu DefectDojo está publicado por nginx en host:8086.
            # Desde el contenedor del pipeline, usamos 172.17.0.1:8086.
            # Si nginx exige Host, forzamos Host: localhost.
            HOST_HDR="Host: localhost"

            echo "[*] Probando token contra /users/me/"
            curl -s -k -H "$AUTH" -H "Accept: application/json" -H "$HOST_HDR" \
              "$DEFECTDOJO_URL/api/v2/users/me/" | jq . >/dev/null

            # 1) Buscar product type (si no existe, usa 1 por defecto)
            # En muchos setups de dojo, prod_type=1 existe (por defecto).
            PROD_TYPE_ID="1"

            # 2) Buscar o crear producto
            PROD_LIST="$(curl -s -k -H "$AUTH" -H "Accept: application/json" -H "$HOST_HDR" \
              "$DEFECTDOJO_URL/api/v2/products/?limit=200")"

            PRODUCT_ID="$(echo "$PROD_LIST" | jq -r '.results[] | select(.name=="'"$PRODUCT_NAME"'") | .id' | head -n 1 || true)"

            if [ -z "${PRODUCT_ID:-}" ]; then
              echo "[*] Producto no existe; creando..."
              CREATE_OUT="$(curl -s -k -H "$AUTH" -H "Content-Type: application/json" -H "Accept: application/json" -H "$HOST_HDR" \
                -X POST "$DEFECTDOJO_URL/api/v2/products/" \
                -d '{"name":"'"$PRODUCT_NAME"'","description":"Aplicación vulnerable usada en el pipeline de CI/CD","prod_type":'"$PROD_TYPE_ID"'}')"
              PRODUCT_ID="$(echo "$CREATE_OUT" | jq -r '.id // empty')"
            fi

            test -n "${PRODUCT_ID:-}"
            echo "[*] PRODUCT_ID=$PRODUCT_ID"

            # 3) Crear engagement
            TODAY="$(date +%Y-%m-%d)"
            END="$(date -d '+30 days' +%Y-%m-%d 2>/dev/null || date -v+30d +%Y-%m-%d)"

            ENG_OUT="$(curl -s -k -H "$AUTH" -H "Content-Type: application/json" -H "Accept: application/json" -H "$HOST_HDR" \
              -X POST "$DEFECTDOJO_URL/api/v2/engagements/" \
              -d '{"name":"'"$ENGAGEMENT_NAME"'","product":'"$PRODUCT_ID"',"engagement_type":"CI/CD","status":"In Progress","target_start":"'"$TODAY"'","target_end":"'"$END"'"}')"

            ENGAGEMENT_ID="$(echo "$ENG_OUT" | jq -r '.id // empty')"
            test -n "${ENGAGEMENT_ID:-}"
            echo "[*] ENGAGEMENT_ID=$ENGAGEMENT_ID"

            # 4) Subir reportes (import-scan)
            echo "== Import Bandit =="
            curl -s -k -H "$AUTH" -H "$HOST_HDR" \
              -F "file=@bandit-report.json" \
              -F "scan_type=Bandit Scan" \
              -F "product=$PRODUCT_ID" \
              -F "engagement=$ENGAGEMENT_ID" \
              "$DEFECTDOJO_URL/api/v2/import-scan/" >/dev/null

            echo "== Import CycloneDX =="
            if [ -s sbom.json ]; then
              SBOM_FILE="sbom.json"
            else
              SBOM_FILE="sbom.xml"
            fi
            curl -s -k -H "$AUTH" -H "$HOST_HDR" \
              -F "file=@$SBOM_FILE" \
              -F "scan_type=$SBOM_SCAN_TYPE" \
              -F "product=$PRODUCT_ID" \
              -F "engagement=$ENGAGEMENT_ID" \
              "$DEFECTDOJO_URL/api/v2/import-scan/" >/dev/null

            echo "== Import Gitleaks =="
            curl -s -k -H "$AUTH" -H "$HOST_HDR" \
              -F "file=@gitleaks-report.json" \
              -F "scan_type=Gitleaks Scan" \
              -F "product=$PRODUCT_ID" \
              -F "engagement=$ENGAGEMENT_ID" \
              "$DEFECTDOJO_URL/api/v2/import-scan/" >/dev/null

            echo "[OK] Reportes importados en DefectDojo"
          '''
        }
      }
    }
  }

  post {
    always {
      sh '''
        set +e
        echo "Archivos generados:"
        ls -la src/bandit-report.json src/gitleaks-report.json src/sbom.json src/sbom.xml 2>/dev/null || true
        echo "Gate summary:"
        cat gate_summary.txt 2>/dev/null || true
      '''
      archiveArtifacts artifacts: 'src/*.json,src/*.xml,gate_summary.txt,dtrack_project_uuid.txt', allowEmptyArchive: true
    }
  }
}