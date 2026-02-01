stage('Upload SBOM to Dependency-Track') {
  steps {
    withCredentials([string(credentialsId: 'dtrack-api-key', variable: 'DTRACK_KEY')]) {
      sh '''
        set -euo pipefail
        cd src

        # Ajusta esto a tu entorno
        DTRACK_URL="http://host.docker.internal:8084"
        PRODUCT_NAME="PyGoat"
        DTRACK_VERSION="1.0"

        # 1) Elegir SBOM
        if [ -s sbom.json ]; then
          SBOM_FILE="sbom.json"
        elif [ -s sbom.xml ]; then
          SBOM_FILE="sbom.xml"
        else
          echo "ERROR: No existe sbom.json ni sbom.xml"
          exit 1
        fi
        echo "[*] Usando SBOM_FILE=$SBOM_FILE"

        # 2) Lookup del proyecto
        LOOKUP_JSON="$(curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Accept: application/json" \
          "$DTRACK_URL/api/v1/project/lookup?name=$PRODUCT_NAME&version=$DTRACK_VERSION" || true)"

        PROJECT_UUID="$(echo "$LOOKUP_JSON" | jq -r '.uuid // empty' 2>/dev/null || true)"

        # 3) Si no existe, crearlo  ✅ AQUÍ VA TU BLOQUE PAYLOAD
        if [ -z "$PROJECT_UUID" ]; then
          echo "[*] Proyecto no existe; creando..."

          PAYLOAD="$(jq -n \
            --arg name "$PRODUCT_NAME" \
            --arg version "$DTRACK_VERSION" \
            --arg description "Proyecto PyGoat en pipeline CI/CD" \
            --arg classifier "APPLICATION" \
            '{name:$name, version:$version, description:$description, classifier:$classifier}')"

          HTTP_CREATE="$(curl -sS -o /tmp/dt_create_resp.json -w "%{http_code}" \
            -H "X-Api-Key: $DTRACK_KEY" -H "Content-Type: application/json" \
            -d "$PAYLOAD" \
            "$DTRACK_URL/api/v1/project")"

          echo "[*] Create project HTTP: $HTTP_CREATE"
          cat /tmp/dt_create_resp.json || true
          echo

          # 200/201 OK. 409 si ya existía (race condition)
          if [ "$HTTP_CREATE" = "200" ] || [ "$HTTP_CREATE" = "201" ]; then
            PROJECT_UUID="$(jq -r '.uuid // empty' /tmp/dt_create_resp.json)"
          elif [ "$HTTP_CREATE" = "409" ]; then
            LOOKUP_JSON="$(curl -sfL -H "X-Api-Key: $DTRACK_KEY" -H "Accept: application/json" \
              "$DTRACK_URL/api/v1/project/lookup?name=$PRODUCT_NAME&version=$DTRACK_VERSION")"
            PROJECT_UUID="$(echo "$LOOKUP_JSON" | jq -r '.uuid')"
          else
            echo "ERROR: No se pudo crear proyecto en Dependency-Track (HTTP $HTTP_CREATE)"
            exit 1
          fi
        fi

        if [ -z "$PROJECT_UUID" ]; then
          echo "ERROR: No se pudo obtener UUID del proyecto"
          exit 1
        fi
        echo "[*] PROJECT_UUID=$PROJECT_UUID"

        # 4) Subir BOM (SBOM) al proyecto
        HTTP_BOM="$(curl -sS -o /tmp/dt_bom_resp.json -w "%{http_code}" \
          -H "X-Api-Key: $DTRACK_KEY" \
          -F "project=$PROJECT_UUID" \
          -F "bom=@$SBOM_FILE" \
          "$DTRACK_URL/api/v1/bom")"

        echo "[*] BOM upload HTTP: $HTTP_BOM"
        cat /tmp/dt_bom_resp.json || true
        echo

        if [ "$HTTP_BOM" != "200" ] && [ "$HTTP_BOM" != "201" ] && [ "$HTTP_BOM" != "202" ]; then
          echo "ERROR: Falló la carga del BOM (HTTP $HTTP_BOM)"
          exit 1
        fi

        echo "[OK] SBOM subido correctamente a Dependency-Track"
      '''
    }
  }
}
