from __future__ import annotations

from typing import Annotated ,Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from langflow.api.utils import DbSession
from langflow.api.v1.schemas import Token
from langflow.initial_setup.setup import get_or_create_default_folder
from langflow.services.auth.utils import (
    authenticate_user,
    authenticate_user_sso,
    create_refresh_token,
    create_user_longterm_token,
    create_user_tokens,
)
from langflow.services.auth.constants import *
from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.deps import get_settings_service, get_variable_service
import base64
import json
import httpx
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import RedirectResponse , JSONResponse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from jose import jwt
from jose.exceptions import JWTError
import os
from dotenv import load_dotenv
import jwt
from langflow.logging.logger import configure, logger
import urllib.parse

router = APIRouter(tags=["Login"])

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
CLIENT_ID = os.getenv("CLIENT_ID")
REALM_NAME = os.getenv("REALM_NAME")
REDIRECT_BASE_URI = os.getenv("REDIRECT_BASE_URI")




@router.post("/login", response_model=Token)
async def login_to_get_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession, # type: ignore
):
    auth_settings = get_settings_service().auth_settings
    try:
        user = await authenticate_user(form_data.username, form_data.password, db)
    except Exception as exc:
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc

    if user:
        tokens = await create_user_tokens(user_id=user.id, db=db, update_last_login=True)
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "apikey_tkn_lflw",
            str(user.store_api_key),
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Set to None to make it a session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )
        await get_variable_service().initialize_user_variables(user.id, db)
        # Create default folder for user if it doesn't exist
        _ = await get_or_create_default_folder(db, user.id)
        return tokens
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/auto_login")
async def auto_login(response: Response, db: DbSession): # type: ignore
    auth_settings = get_settings_service().auth_settings

    if auth_settings.AUTO_LOGIN:
        user_id, tokens = await create_user_longterm_token(db)
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Set to None to make it a session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )

        user = await get_user_by_id(db, user_id)

        if user:
            if user.store_api_key is None:
                user.store_api_key = ""

            response.set_cookie(
                "apikey_tkn_lflw",
                str(user.store_api_key),  # Ensure it's a string
                httponly=auth_settings.ACCESS_HTTPONLY,
                samesite=auth_settings.ACCESS_SAME_SITE,
                secure=auth_settings.ACCESS_SECURE,
                expires=None,  # Set to None to make it a session cookie
                domain=auth_settings.COOKIE_DOMAIN,
            )

        return tokens

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "message": "Auto login is disabled. Please enable it in the settings",
            "auto_login": False,
        },
    )


@router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    db: DbSession,
):
    auth_settings = get_settings_service().auth_settings

    token = request.cookies.get("refresh_token_lf")

    if token:
        tokens = await create_refresh_token(token, db)
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        return tokens
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("refresh_token_lf")
    response.delete_cookie("access_token_lf")
    response.delete_cookie("apikey_tkn_lflw")
    response.delete_cookie("resource_access")
    response.delete_cookie("user_roles")
    return {"message": "Logout successful"}

async def decode_jwt(access_token):
    decoded_token = jwt.decode(access_token, options={"verify_signature": False})  # Skip signature verification
    microsoft = {
        "resource_access":decoded_token.get("realm_access", {}).get("roles"),
        "user_roles":decoded_token.get("groups"),
        "Email": decoded_token.get("email"),
        "UserType": "Microsoft",
        "Name": decoded_token.get("name"),
        "Username": decoded_token.get("preferred_username"),
        "FirstName": decoded_token.get("given_name"),
        "LastName": decoded_token.get("family_name")
    }

    return microsoft

 # Example 16-byte AES key for encryption (must be 16, 24, or 32 bytes long)


def encrypt_string_to_bytes(bson_string: str):
    """Encrypt a string using AES encryption and return the encrypted result as a base64 encoded string."""
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC)
    padded_data = pad(bson_string.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    iv = base64.urlsafe_b64encode(cipher.iv).decode('utf-8')  # encode IV as base64 to send as a string
    encrypted_string = base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
    return iv + ":" + encrypted_string  # Return IV and encrypted string separated by colon


# Function to decrypt the string using AES
def decrypt_string_from_bytes(encrypted_string: str):
    """Decrypt a base64 encoded encrypted string and return the original BSON string."""
    iv_base64, encrypted_base64 = encrypted_string.split(":")
    iv = base64.urlsafe_b64decode(iv_base64)
    encrypted_data = base64.urlsafe_b64decode(encrypted_base64)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode('utf-8')



@router.get("sso/login")
async def login(request: Request):
    try:
        # Example BSON query to encrypt
        bson_query = {
            "inv": "0",  # Example value for 'inv'
            "tn": "0",   # Example value for 'tn'
        }
        bson_string = json.dumps(bson_query)
        
        # Encrypt the BSON query string
        encrypted_query_string = encrypt_string_to_bytes(bson_string)

        # Get base URL from request
        base_url = str(request.base_url)

        # Construct Keycloak URL
        keycloak_auth_url = (
            f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth?"
            f"client_id={CLIENT_ID}&redirect_uri={base_url}{REDIRECT_BASE_URI}?inv={encrypted_query_string}"
            f"&response_type=code&scope=openid&kc_idp_hint=microsoft"
        )
        
        # Redirect to Keycloak authentication
        return RedirectResponse(url=keycloak_auth_url)

    except Exception as e:
        # Handle exceptions by returning an HTTP error with the message
        raise HTTPException(status_code=500, detail=f"Error occurred during login: {str(e)}")


async def get_keycloak_jwt_token(code: str, inv: str ,base_url :str):
    try:
        # Construct the token request URL
        token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"
        data = {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": f"{base_url}{REDIRECT_BASE_URI}?inv={inv}",
            "code": code
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(token_url, data=data)
            response.raise_for_status()
            token = response.json()
            

            return token.get("access_token")
        
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Keycloak token request failed: {e}")
    except httpx.RequestError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error requesting token: {e}")

# Endpoint to handle the redirect from Keycloak after successful login


@router.get("/SSO/KeyCloakAuthCheck")
async def keycloak_auth_check(
    code: str, 
    request: Request, 
    response: Response, 
    db: DbSession,
    inv: Optional[str] = None
):
    # Check if 'code' parameter is provided
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Code not received"
        )

    # Decrypt the 'inv' parameter if it exists
    if inv:
        try:
            decrypted_inv = decrypt_string_from_bytes(inv)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="Invalid 'inv' parameter"
            )
    
    # Prepare base URL from request
    base_url = str(request.base_url)

    # Attempt to get access token from Keycloak
    try:
        access_token = await get_keycloak_jwt_token(code, inv, base_url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Unable to get token from Keycloak"
        )

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Unable to get token from Keycloak"
        )

    # Attempt to decode the JWT token
    try:
        user_info = await decode_jwt(access_token)
        logger.info(f"KeyClock_access :{access_token}")
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid JWT token"
        )

    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Invalid JWT token"
        )

    auth_settings = get_settings_service().auth_settings

    # Attempt to authenticate user from the decoded user information
    try:
        user = await authenticate_user_sso(user_info.get('Email'), db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Error authenticating user"
        )

    # Handle different user statuses
    if user == "Inactive user" or user == "Waiting for approval":
        redirect_url = base_url.replace("http://", "https://")
        redirect_url = f"{redirect_url}login?error={user}"
        return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

    elif user:
        # Create user tokens and set cookies
        try:
            tokens = await create_user_tokens(user_id=user.id, db=db, update_last_login=True)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Error creating user tokens"
            )

        # Prepare the redirect URL and set cookies for the user session
        redirect_url = base_url.replace("http://", "https://") + "flow"
        response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
        
        response.set_cookie(
            "resource_access",
            urllib.parse.quote(json.dumps(user_info["resource_access"])),
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "user_roles",
            urllib.parse.quote(json.dumps(user_info["user_roles"])),
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "refresh_token_lf",
            tokens["refresh_token"],
            httponly=auth_settings.REFRESH_HTTPONLY,
            samesite=auth_settings.REFRESH_SAME_SITE,
            secure=auth_settings.REFRESH_SECURE,
            expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "access_token_lf",
            tokens["access_token"],
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
            domain=auth_settings.COOKIE_DOMAIN,
        )
        response.set_cookie(
            "apikey_tkn_lflw",
            str(user.store_api_key),
            httponly=auth_settings.ACCESS_HTTPONLY,
            samesite=auth_settings.ACCESS_SAME_SITE,
            secure=auth_settings.ACCESS_SECURE,
            expires=None,  # Session cookie
            domain=auth_settings.COOKIE_DOMAIN,
        )

        # Initialize user variables and create default folder if needed
        try:
            await get_variable_service().initialize_user_variables(user.id, db)
            _ = await get_or_create_default_folder(db, user.id)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                detail="Error initializing user variables or creating default folder"
            )

        return response

    # Default error if no valid user found
    redirect_url = base_url.replace("http://", "https://")
    redirect_url = f"{redirect_url}login?error=InvalidCredentials"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
