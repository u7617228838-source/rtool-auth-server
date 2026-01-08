"""
Servidor privado para manejar Auth0 token exchange
Esto mantiene el CLIENT_SECRET seguro (nunca en el .exe)

Para desplegar en Render.com:
1. Crea cuenta en https://render.com
2. Conecta tu GitHub
3. Deploy este archivo como Web Service
4. En variables de entorno añade:
   - AUTH0_DOMAIN=tu_dominio.auth0.com
   - AUTH0_CLIENT_ID=tu_client_id
   - AUTH0_CLIENT_SECRET=tu_client_secret_aqui
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import logging

app = Flask(__name__)
CORS(app)

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Variables de entorno (en Render, se configuran en el dashboard)
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")

# Validar que las variables estén configuradas
if not all([AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET]):
    logger.error("❌ FALTA CONFIGURAR: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET")
    logger.error("   En Render dashboard: Settings → Environment")
else:
    logger.info(f"✅ Auth0 configurado para dominio: {AUTH0_DOMAIN}")


@app.route("/health", methods=["GET"])
def health():
    """Endpoint de verificación de que el servidor está vivo"""
    return jsonify({"status": "ok", "message": "RTool Auth Server activo"}), 200


@app.route("/api/auth/token", methods=["POST"])
def exchange_token():
    """
    Endpoint para intercambiar código por token
    
    Recibe:
    {
        "code": "código_de_auth0",
        "code_verifier": "pkce_verifier",
        "redirect_uri": "http://localhost:8080/callback"
    }
    
    Devuelve:
    {
        "access_token": "token...",
        "token_type": "Bearer",
        "expires_in": 86400,
        "id_token": "...",
        "user_info": {email: "...", ...}
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No se envió JSON"}), 400
        
        code = data.get("code")
        code_verifier = data.get("code_verifier")
        redirect_uri = data.get("redirect_uri")
        
        if not all([code, code_verifier, redirect_uri]):
            return jsonify({
                "error": "Falta parámetro",
                "required": ["code", "code_verifier", "redirect_uri"]
            }), 400
        
        # Intercambiar código por token (aquí se usa el CLIENT_SECRET de forma segura)
        token_url = f"https://{AUTH0_DOMAIN}/oauth/token"
        
        payload = {
            'client_id': AUTH0_CLIENT_ID,
            'client_secret': AUTH0_CLIENT_SECRET,  # ✅ SECRET SEGURO EN SERVIDOR
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
            'code_verifier': code_verifier,
        }
        
        logger.info(f"📤 Intercambiando código con Auth0...")
        response = requests.post(token_url, json=payload, timeout=10)
        response.raise_for_status()
        
        token_data = response.json()
        logger.info(f"✅ Token obtenido exitosamente")
        
        # Obtener información del usuario (opcional pero útil)
        user_info = {}
        if 'access_token' in token_data:
            try:
                userinfo_url = f"https://{AUTH0_DOMAIN}/userinfo"
                headers = {'Authorization': f"Bearer {token_data['access_token']}"}
                userinfo_response = requests.get(userinfo_url, headers=headers, timeout=10)
                if userinfo_response.status_code == 200:
                    user_info = userinfo_response.json()
                    logger.info(f"✅ Usuario: {user_info.get('email', 'desconocido')}")
            except Exception as e:
                logger.warning(f"⚠️  No se pudo obtener user_info: {e}")
        
        # Devolver token e información del usuario
        return jsonify({
            "success": True,
            "access_token": token_data.get("access_token"),
            "token_type": token_data.get("token_type", "Bearer"),
            "expires_in": token_data.get("expires_in"),
            "id_token": token_data.get("id_token"),
            "user_info": user_info
        }), 200
    
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Error contactando Auth0: {e}")
        return jsonify({
            "error": "Error contactando Auth0",
            "details": str(e)
        }), 500
    
    except Exception as e:
        logger.error(f"❌ Error inesperado: {e}")
        return jsonify({
            "error": "Error interno del servidor",
            "details": str(e)
        }), 500


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    """
    Endpoint opcional para logout
    Devuelve la URL para desconectarse de Auth0
    """
    try:
        data = request.get_json() or {}
        return_to = data.get("return_to", "")
        
        logout_url = f"https://{AUTH0_DOMAIN}/v2/logout?client_id={AUTH0_CLIENT_ID}"
        if return_to:
            logout_url += f"&returnTo={return_to}"
        
        return jsonify({
            "logout_url": logout_url
        }), 200
    
    except Exception as e:
        logger.error(f"❌ Error en logout: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # Para desarrollo local
    app.run(debug=True, host="0.0.0.0", port=5000)
