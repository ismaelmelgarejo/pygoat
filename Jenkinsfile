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

  environment {
    // ====== URLs (TU SETUP) ======
    // OJO: en Mac suele funcionar mejor host.docker.internal
    DTRACK_URL     = "http://host.docker.internal:8084"
    DEFECTDOJO_URL = "http://host.docker.internal:8080"

    // ====== Nombres para el ejercicio ======
    PRODUCT_NAME     = "PyGoat"
    DTRACK_VERSION   = "1.0"
    ENGAGEMENT_NAME  = "CI/CD Security Pipeline"
    SBOM_SCAN_TYPE   = "CycloneDX Scan"

    // ====== GATES ======
    ENFORCE_GATES = "false"
    BANDIT_MAX_HIGH   = "0"
    DTRACK_MAX_HIGH   = "0"
    DTRACK_MAX_CRIT   = "0"
  }

  stages {

    stage('Init Workspace') {
      steps {
        sh '''
          set -e
          # limpieza tolerante
          rm -rf ./* ./.??* || true
    '''
      }
    }

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

            if [ -s sbom.json ]; then
              SBOM_FILE="sbom.json"
            else
              SBOM_FILE="sbom.xml"
            fi
            echo "[*] Usando SBOM_FILE=$SBOM_FILE"

            curl -sfL "$DTRACK_URL/api/openapi.json" >/dev/null
            curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Accept: application/json" \
              "$DTRACK_URL/api/version" >/dev/null

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
            echo "$PROJECT_UUID" > ../dtrack_project_uuid.txt

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
          '''
        }
      }
    }

    // ... tus stages restantes igual, pero cambiando cd pygoat -> cd src
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
