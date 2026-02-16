from fastapi import FastAPI, APIRouter, HTTPException, Query, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, date, timedelta
from bson import ObjectId
import jwt
from passlib.context import CryptContext
import secrets
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
import asyncio
from email_service import send_daily_report, send_alert_email


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7  # 7 days

# Scheduler for automatic backups
scheduler = AsyncIOScheduler()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Security
security = HTTPBearer()

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# ==================== CONSTANTS ====================

# Expense Categories for Horses
HORSE_EXPENSE_CATEGORIES = [
    "pupilaje",
    "herrador", 
    "veterinario",
    "dentista",
    "vacunas",
    "desparasitacion",
    "fisioterapia",
    "proveedores",
    "otros_propietarios",
    "alimentacion",
    "equipo",
    "transporte",
    "otros"
]

HORSE_CATEGORY_NAMES = {
    "pupilaje": "Pupilaje",
    "herrador": "Herrador",
    "veterinario": "Veterinario",
    "dentista": "Dentista",
    "vacunas": "Vacunas",
    "desparasitacion": "Desparasitación",
    "fisioterapia": "Fisioterapia",
    "proveedores": "Proveedores",
    "otros_propietarios": "Otros Propietarios",
    "alimentacion": "Alimentación",
    "equipo": "Equipo",
    "transporte": "Transporte",
    "otros": "Otros"
}

# Expense Categories for Riders
RIDER_EXPENSE_CATEGORIES = [
    "equipamiento",
    "formacion",
    "competiciones",
    "licencias",
    "seguros",
    "transporte",
    "alimentacion",
    "fisioterapia",
    "otros"
]

RIDER_CATEGORY_NAMES = {
    "equipamiento": "Equipamiento",
    "formacion": "Formación",
    "competiciones": "Competiciones",
    "licencias": "Licencias",
    "seguros": "Seguros",
    "transporte": "Transporte",
    "alimentacion": "Alimentación",
    "fisioterapia": "Fisioterapia",
    "otros": "Otros"
}

# Competition Disciplines
COMPETITION_DISCIPLINES = [
    "salto",
    "doma_clasica",
    "doma_vaquera",
    "concurso_completo",
    "raid",
    "enganche",
    "reining",
    "volteo",
    "horseball",
    "polo",
    "otros"
]

DISCIPLINE_NAMES = {
    "salto": "Salto",
    "doma_clasica": "Doma Clásica",
    "doma_vaquera": "Doma Vaquera",
    "concurso_completo": "Concurso Completo",
    "raid": "Raid",
    "enganche": "Enganche",
    "reining": "Reining",
    "volteo": "Volteo",
    "horseball": "Horseball",
    "polo": "Polo",
    "otros": "Otros"
}

# ==================== MODELS ====================

# ==================== USER AUTHENTICATION ====================

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str
    language: str = "es"
    security_question: str
    security_answer: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    language: str
    created_at: datetime
    has_security_question: bool = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class SecurityQuestionResponse(BaseModel):
    email: str
    security_question: str

class VerifySecurityAnswerRequest(BaseModel):
    email: EmailStr
    security_answer: str

class ResetPasswordWithSecurityRequest(BaseModel):
    email: EmailStr
    security_answer: str
    new_password: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class ChangeLanguageRequest(BaseModel):
    language: str

# Security questions options
SECURITY_QUESTIONS = [
    "¿Cuál es el nombre de tu primera mascota?",
    "¿En qué ciudad naciste?",
    "¿Cuál es el nombre de tu madre?",
    "¿Cuál fue tu primer colegio?",
    "¿Cuál es tu comida favorita?",
    "¿Cuál es el nombre de tu mejor amigo de la infancia?",
    "¿Cuál es tu película favorita?",
    "¿Cuál es el segundo nombre de tu padre?",
]

# Helper functions for authentication
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def serialize_user(user: dict) -> dict:
    return {
        "id": str(user["_id"]),
        "email": user.get("email", ""),
        "name": user.get("name", ""),
        "language": user.get("language", "es"),
        "created_at": user.get("created_at", datetime.utcnow()),
        "has_security_question": bool(user.get("security_question"))
    }

# Document Model for PDFs
class Document(BaseModel):
    name: str
    data: str  # Base64 encoded PDF
    uploaded_at: Optional[str] = None

# Horse Models
class HorseBase(BaseModel):
    name: str
    breed: Optional[str] = None
    birth_date: Optional[str] = None
    color: Optional[str] = None
    notes: Optional[str] = None
    photo: Optional[str] = None
    photos: Optional[List[str]] = []
    stabling_location: Optional[str] = None
    territorial_license: Optional[str] = None
    national_license: Optional[str] = None
    owner: Optional[str] = None  # New field: Owner name
    documents: Optional[List[dict]] = []  # New field: List of PDF documents

class HorseCreate(HorseBase):
    pass

class HorseUpdate(BaseModel):
    name: Optional[str] = None
    breed: Optional[str] = None
    birth_date: Optional[str] = None
    color: Optional[str] = None
    notes: Optional[str] = None
    photo: Optional[str] = None
    photos: Optional[List[str]] = None
    stabling_location: Optional[str] = None
    territorial_license: Optional[str] = None
    national_license: Optional[str] = None
    owner: Optional[str] = None
    documents: Optional[List[dict]] = None

class Horse(HorseBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Rider Models
class RiderBase(BaseModel):
    name: str
    photo: Optional[str] = None
    photos: Optional[List[str]] = []
    birth_date: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    notes: Optional[str] = None
    territorial_license: Optional[str] = None
    national_license: Optional[str] = None
    documents: Optional[List[dict]] = []  # New field: List of PDF documents

class RiderCreate(RiderBase):
    pass

class RiderUpdate(BaseModel):
    name: Optional[str] = None
    photo: Optional[str] = None
    photos: Optional[List[str]] = None
    birth_date: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    notes: Optional[str] = None
    territorial_license: Optional[str] = None
    national_license: Optional[str] = None
    documents: Optional[List[dict]] = None

class Rider(RiderBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Supplier Models
class SupplierBase(BaseModel):
    name: str
    category: Optional[str] = None
    custom_category: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    notes: Optional[str] = None
    contact_person: Optional[str] = None

class SupplierCreate(SupplierBase):
    pass

class SupplierUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    custom_category: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    address: Optional[str] = None
    city: Optional[str] = None
    notes: Optional[str] = None
    contact_person: Optional[str] = None

class Supplier(SupplierBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Horse-Rider Association
class HorseRiderAssociation(BaseModel):
    horse_id: str
    rider_id: str

# Expense Models (for horses) - Updated with multiple invoice photos and custom_category
class ExpenseBase(BaseModel):
    horse_id: str
    category: str
    custom_category: Optional[str] = None
    amount: float
    date: str
    description: Optional[str] = None
    provider: Optional[str] = None
    supplier_id: Optional[str] = None
    invoice_photo: Optional[str] = None  # Legacy single photo
    invoice_photos: Optional[List[str]] = []  # New: Multiple photos (base64)
    is_recurring: Optional[bool] = False  # New: Monthly recurring expense
    create_reminder: Optional[bool] = True  # New: Create automatic reminder

class ExpenseCreate(ExpenseBase):
    pass

class ExpenseUpdate(BaseModel):
    horse_id: Optional[str] = None
    category: Optional[str] = None
    custom_category: Optional[str] = None
    amount: Optional[float] = None
    date: Optional[str] = None
    description: Optional[str] = None
    provider: Optional[str] = None
    supplier_id: Optional[str] = None
    invoice_photo: Optional[str] = None
    invoice_photos: Optional[List[str]] = None
    is_recurring: Optional[bool] = None
    create_reminder: Optional[bool] = None

class Expense(ExpenseBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Rider Expense Models - Updated with multiple invoice photos and custom_category
class RiderExpenseBase(BaseModel):
    rider_id: str
    category: str
    custom_category: Optional[str] = None
    amount: float
    date: str
    description: Optional[str] = None
    provider: Optional[str] = None
    supplier_id: Optional[str] = None
    invoice_photo: Optional[str] = None  # Legacy single photo
    invoice_photos: Optional[List[str]] = []  # New: Multiple photos (base64)
    is_recurring: Optional[bool] = False  # New: Monthly recurring expense
    create_reminder: Optional[bool] = True  # New: Create automatic reminder

class RiderExpenseCreate(RiderExpenseBase):
    pass

class RiderExpenseUpdate(BaseModel):
    rider_id: Optional[str] = None
    category: Optional[str] = None
    custom_category: Optional[str] = None
    amount: Optional[float] = None
    date: Optional[str] = None
    description: Optional[str] = None
    provider: Optional[str] = None
    supplier_id: Optional[str] = None
    invoice_photo: Optional[str] = None
    invoice_photos: Optional[List[str]] = None
    is_recurring: Optional[bool] = None
    create_reminder: Optional[bool] = None

class RiderExpense(RiderExpenseBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Palmares (Rider Achievements) Models
class PalmaresBase(BaseModel):
    rider_id: str
    competition_name: str
    date: str
    place: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = "España"
    location_link: Optional[str] = None  # New: Link to location (Google Maps, etc.)
    discipline: str
    custom_discipline: Optional[str] = None
    position: Optional[str] = None
    horse_id: Optional[str] = None
    category: Optional[str] = None
    notes: Optional[str] = None
    prize: Optional[str] = None

class PalmaresCreate(PalmaresBase):
    pass

class PalmaresUpdate(BaseModel):
    competition_name: Optional[str] = None
    date: Optional[str] = None
    place: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    location_link: Optional[str] = None
    discipline: Optional[str] = None
    custom_discipline: Optional[str] = None
    position: Optional[str] = None
    horse_id: Optional[str] = None
    category: Optional[str] = None
    notes: Optional[str] = None
    prize: Optional[str] = None

class Palmares(PalmaresBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Competition Models
class CompetitionBase(BaseModel):
    name: str
    date: str
    end_date: Optional[str] = None
    place: str
    city: str
    country: Optional[str] = "España"
    location_link: Optional[str] = None  # New: Link to location (Google Maps, etc.)
    discipline: str
    custom_discipline: Optional[str] = None
    level: Optional[str] = None
    organizer: Optional[str] = None
    entry_deadline: Optional[str] = None
    entry_fee: Optional[float] = None
    notes: Optional[str] = None
    website: Optional[str] = None
    contact_phone: Optional[str] = None
    contact_email: Optional[str] = None
    accommodation_info: Optional[str] = None
    participating_horses: Optional[List[str]] = []
    participating_riders: Optional[List[str]] = []

class CompetitionCreate(CompetitionBase):
    pass

class CompetitionUpdate(BaseModel):
    name: Optional[str] = None
    date: Optional[str] = None
    end_date: Optional[str] = None
    place: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    location_link: Optional[str] = None
    discipline: Optional[str] = None
    custom_discipline: Optional[str] = None
    level: Optional[str] = None
    organizer: Optional[str] = None
    entry_deadline: Optional[str] = None
    entry_fee: Optional[float] = None
    notes: Optional[str] = None
    website: Optional[str] = None
    contact_phone: Optional[str] = None
    contact_email: Optional[str] = None
    accommodation_info: Optional[str] = None
    participating_horses: Optional[List[str]] = None
    participating_riders: Optional[List[str]] = None

class Competition(CompetitionBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Reminder Models
class ReminderBase(BaseModel):
    title: str
    description: Optional[str] = None
    reminder_date: str
    reminder_time: Optional[str] = "18:00"
    entity_type: str
    entity_id: Optional[str] = None
    category: Optional[str] = None
    is_automatic: bool = False
    is_completed: bool = False
    competition_id: Optional[str] = None
    priority: Optional[str] = "info"  # info, importante, urgente
    interval_days: Optional[int] = None  # Para reprogramación automática

class ReminderCreate(ReminderBase):
    pass

class ReminderUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    reminder_date: Optional[str] = None
    reminder_time: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    category: Optional[str] = None
    is_completed: Optional[bool] = None
    priority: Optional[str] = None
    interval_days: Optional[int] = None

class Reminder(ReminderBase):
    id: str
    created_at: datetime
    updated_at: datetime

# Budget Models
class BudgetBase(BaseModel):
    entity_type: str
    entity_id: Optional[str] = None
    category: Optional[str] = None
    month: int
    year: int
    amount: float

class BudgetCreate(BudgetBase):
    pass

class BudgetUpdate(BaseModel):
    amount: Optional[float] = None

class Budget(BudgetBase):
    id: str
    created_at: datetime
    updated_at: datetime

# ==================== HELPER FUNCTIONS ====================

def serialize_horse(horse: dict) -> dict:
    return {
        "id": str(horse["_id"]),
        "name": horse.get("name", ""),
        "breed": horse.get("breed"),
        "birth_date": horse.get("birth_date"),
        "color": horse.get("color"),
        "notes": horse.get("notes"),
        "photo": horse.get("photo"),
        "photos": horse.get("photos", []),
        "stabling_location": horse.get("stabling_location"),
        "territorial_license": horse.get("territorial_license"),
        "national_license": horse.get("national_license"),
        "owner": horse.get("owner"),
        "documents": horse.get("documents", []),
        "created_at": horse.get("created_at", datetime.utcnow()),
        "updated_at": horse.get("updated_at", datetime.utcnow())
    }

def serialize_rider(rider: dict) -> dict:
    return {
        "id": str(rider["_id"]),
        "name": rider.get("name", ""),
        "photo": rider.get("photo"),
        "photos": rider.get("photos", []),
        "birth_date": rider.get("birth_date"),
        "phone": rider.get("phone"),
        "email": rider.get("email"),
        "notes": rider.get("notes"),
        "territorial_license": rider.get("territorial_license"),
        "national_license": rider.get("national_license"),
        "documents": rider.get("documents", []),
        "created_at": rider.get("created_at", datetime.utcnow()),
        "updated_at": rider.get("updated_at", datetime.utcnow())
    }

def serialize_supplier(supplier: dict) -> dict:
    return {
        "id": str(supplier["_id"]),
        "name": supplier.get("name", ""),
        "category": supplier.get("category"),
        "custom_category": supplier.get("custom_category"),
        "phone": supplier.get("phone"),
        "email": supplier.get("email"),
        "address": supplier.get("address"),
        "city": supplier.get("city"),
        "notes": supplier.get("notes"),
        "contact_person": supplier.get("contact_person"),
        "created_at": supplier.get("created_at", datetime.utcnow()),
        "updated_at": supplier.get("updated_at", datetime.utcnow())
    }

def serialize_expense(expense: dict) -> dict:
    return {
        "id": str(expense["_id"]),
        "horse_id": expense.get("horse_id", ""),
        "category": expense.get("category", ""),
        "custom_category": expense.get("custom_category"),
        "amount": expense.get("amount", 0),
        "date": expense.get("date", ""),
        "description": expense.get("description"),
        "provider": expense.get("provider"),
        "supplier_id": expense.get("supplier_id"),
        "invoice_photo": expense.get("invoice_photo"),
        "invoice_photos": expense.get("invoice_photos", []),
        "created_at": expense.get("created_at", datetime.utcnow()),
        "updated_at": expense.get("updated_at", datetime.utcnow())
    }

def serialize_rider_expense(expense: dict) -> dict:
    return {
        "id": str(expense["_id"]),
        "rider_id": expense.get("rider_id", ""),
        "category": expense.get("category", ""),
        "custom_category": expense.get("custom_category"),
        "amount": expense.get("amount", 0),
        "date": expense.get("date", ""),
        "description": expense.get("description"),
        "provider": expense.get("provider"),
        "supplier_id": expense.get("supplier_id"),
        "invoice_photo": expense.get("invoice_photo"),
        "invoice_photos": expense.get("invoice_photos", []),
        "created_at": expense.get("created_at", datetime.utcnow()),
        "updated_at": expense.get("updated_at", datetime.utcnow())
    }

def serialize_palmares(palmares: dict) -> dict:
    return {
        "id": str(palmares["_id"]),
        "rider_id": palmares.get("rider_id", ""),
        "competition_name": palmares.get("competition_name", ""),
        "date": palmares.get("date", ""),
        "place": palmares.get("place"),
        "city": palmares.get("city"),
        "country": palmares.get("country", "España"),
        "location_link": palmares.get("location_link"),
        "discipline": palmares.get("discipline", ""),
        "custom_discipline": palmares.get("custom_discipline"),
        "position": palmares.get("position"),
        "horse_id": palmares.get("horse_id"),
        "category": palmares.get("category"),
        "notes": palmares.get("notes"),
        "prize": palmares.get("prize"),
        "created_at": palmares.get("created_at", datetime.utcnow()),
        "updated_at": palmares.get("updated_at", datetime.utcnow())
    }

def serialize_competition(competition: dict) -> dict:
    return {
        "id": str(competition["_id"]),
        "name": competition.get("name", ""),
        "date": competition.get("date", ""),
        "end_date": competition.get("end_date"),
        "place": competition.get("place", ""),
        "city": competition.get("city", ""),
        "country": competition.get("country", "España"),
        "location_link": competition.get("location_link"),
        "discipline": competition.get("discipline", ""),
        "custom_discipline": competition.get("custom_discipline"),
        "level": competition.get("level"),
        "organizer": competition.get("organizer"),
        "entry_deadline": competition.get("entry_deadline"),
        "entry_fee": competition.get("entry_fee"),
        "notes": competition.get("notes"),
        "website": competition.get("website"),
        "contact_phone": competition.get("contact_phone"),
        "contact_email": competition.get("contact_email"),
        "accommodation_info": competition.get("accommodation_info"),
        "participating_horses": competition.get("participating_horses", []),
        "participating_riders": competition.get("participating_riders", []),
        "created_at": competition.get("created_at", datetime.utcnow()),
        "updated_at": competition.get("updated_at", datetime.utcnow())
    }

def serialize_reminder(reminder: dict) -> dict:
    return {
        "id": str(reminder["_id"]),
        "title": reminder.get("title", ""),
        "description": reminder.get("description"),
        "reminder_date": reminder.get("reminder_date", ""),
        "reminder_time": reminder.get("reminder_time", "18:00"),
        "entity_type": reminder.get("entity_type", "horse"),
        "entity_id": reminder.get("entity_id"),
        "category": reminder.get("category"),
        "is_automatic": reminder.get("is_automatic", False),
        "is_completed": reminder.get("is_completed", False),
        "competition_id": reminder.get("competition_id"),
        "priority": reminder.get("priority", "info"),
        "interval_days": reminder.get("interval_days"),
        "is_preaviso": reminder.get("is_preaviso", False),
        "last_completed_date": reminder.get("last_completed_date"),
        "created_at": reminder.get("created_at", datetime.utcnow()),
        "updated_at": reminder.get("updated_at", datetime.utcnow())
    }

def serialize_budget(budget: dict) -> dict:
    return {
        "id": str(budget["_id"]),
        "entity_type": budget.get("entity_type", "horse"),
        "entity_id": budget.get("entity_id"),
        "category": budget.get("category"),
        "month": budget.get("month", 1),
        "year": budget.get("year", datetime.now().year),
        "amount": budget.get("amount", 0),
        "created_at": budget.get("created_at", datetime.utcnow()),
        "updated_at": budget.get("updated_at", datetime.utcnow())
    }

# ==================== ROUTES ====================

@api_router.get("/")
async def root():
    return {"message": "Horse Expense Tracker API v3"}

@api_router.get("/health")
@api_router.head("/health")
async def health_check():
    """Health check endpoint for deployment monitoring"""
    try:
        # Test MongoDB connection
        await db.command("ping")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": str(e)}

@api_router.get("/categories")
async def get_categories():
    return {
        "horse_categories": HORSE_EXPENSE_CATEGORIES,
        "horse_names": HORSE_CATEGORY_NAMES,
        "rider_categories": RIDER_EXPENSE_CATEGORIES,
        "rider_names": RIDER_CATEGORY_NAMES,
        "disciplines": COMPETITION_DISCIPLINES,
        "discipline_names": DISCIPLINE_NAMES,
        "categories": HORSE_EXPENSE_CATEGORIES,
        "names": HORSE_CATEGORY_NAMES
    }

# ==================== AUTHENTICATION ROUTES ====================

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email.lower()})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user with security question
    user_dict = {
        "email": user_data.email.lower(),
        "password": hash_password(user_data.password),
        "name": user_data.name,
        "language": user_data.language,
        "security_question": user_data.security_question,
        "security_answer": user_data.security_answer.lower().strip(),  # Normalize for comparison
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_dict)
    user_dict["_id"] = result.inserted_id
    
    # Generate token
    token = create_access_token(str(result.inserted_id))
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": serialize_user(user_dict)
    }

@api_router.get("/auth/security-questions")
async def get_security_questions():
    """Get list of available security questions"""
    return {"questions": SECURITY_QUESTIONS}

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email.lower()})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(str(user["_id"]))
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": serialize_user(user)
    }

@api_router.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return serialize_user(current_user)

@api_router.delete("/auth/delete-account")
async def delete_user_account(current_user: dict = Depends(get_current_user)):
    """Delete user account and all associated data"""
    user_id = current_user["_id"]
    
    # Delete all user data
    await db.horses.delete_many({"user_id": str(user_id)})
    await db.riders.delete_many({"user_id": str(user_id)})
    await db.suppliers.delete_many({"user_id": str(user_id)})
    await db.expenses.delete_many({"user_id": str(user_id)})
    await db.rider_expenses.delete_many({"user_id": str(user_id)})
    await db.competitions.delete_many({"user_id": str(user_id)})
    await db.palmares.delete_many({"user_id": str(user_id)})
    await db.reminders.delete_many({"user_id": str(user_id)})
    await db.budgets.delete_many({"user_id": str(user_id)})
    await db.horse_rider_associations.delete_many({"user_id": str(user_id)})
    
    # Delete user
    await db.users.delete_one({"_id": user_id})
    
    return {"message": "Account and all data deleted successfully"}

@api_router.put("/auth/language")
async def change_language(request: ChangeLanguageRequest, current_user: dict = Depends(get_current_user)):
    if request.language not in ["es", "en"]:
        raise HTTPException(status_code=400, detail="Invalid language. Use 'es' or 'en'")
    
    await db.users.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"language": request.language, "updated_at": datetime.utcnow()}}
    )
    
    return {"message": "Language updated successfully", "language": request.language}

@api_router.post("/auth/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    """Get security question for email - Step 1 of password recovery"""
    user = await db.users.find_one({"email": request.email.lower()})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    
    security_question = user.get("security_question")
    if not security_question:
        raise HTTPException(status_code=400, detail="No security question configured for this account")
    
    return {
        "email": request.email.lower(),
        "security_question": security_question
    }

@api_router.post("/auth/verify-security-answer")
async def verify_security_answer(request: VerifySecurityAnswerRequest):
    """Verify security answer - Step 2 of password recovery"""
    user = await db.users.find_one({"email": request.email.lower()})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    
    stored_answer = user.get("security_answer", "").lower().strip()
    provided_answer = request.security_answer.lower().strip()
    
    if stored_answer != provided_answer:
        raise HTTPException(status_code=401, detail="Incorrect answer")
    
    return {"verified": True, "message": "Answer verified successfully"}

@api_router.post("/auth/reset-password-with-security")
async def reset_password_with_security(request: ResetPasswordWithSecurityRequest):
    """Reset password after verifying security answer - Step 3 of password recovery"""
    user = await db.users.find_one({"email": request.email.lower()})
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")
    
    stored_answer = user.get("security_answer", "").lower().strip()
    provided_answer = request.security_answer.lower().strip()
    
    if stored_answer != provided_answer:
        raise HTTPException(status_code=401, detail="Incorrect security answer")
    
    # Update password
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password": hash_password(request.new_password),
            "updated_at": datetime.utcnow()
        }}
    )
    
    return {"message": "Password reset successfully"}

@api_router.post("/auth/reset-password")
async def reset_password(request: ResetPasswordRequest):
    reset_record = await db.password_resets.find_one({
        "token": request.token,
        "used": False,
        "expires": {"$gt": datetime.utcnow()}
    })
    
    if not reset_record:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    
    # Update password
    await db.users.update_one(
        {"_id": ObjectId(reset_record["user_id"])},
        {"$set": {"password": hash_password(request.new_password), "updated_at": datetime.utcnow()}}
    )
    
    # Mark token as used
    await db.password_resets.update_one(
        {"_id": reset_record["_id"]},
        {"$set": {"used": True}}
    )
    
    return {"message": "Password reset successfully"}

# ==================== HORSE ROUTES ====================

@api_router.post("/horses", response_model=Horse)
async def create_horse(horse: HorseCreate, current_user: dict = Depends(get_current_user)):
    horse_dict = horse.dict()
    horse_dict["user_id"] = str(current_user["_id"])
    horse_dict["created_at"] = datetime.utcnow()
    horse_dict["updated_at"] = datetime.utcnow()
    
    result = await db.horses.insert_one(horse_dict)
    created_horse = await db.horses.find_one({"_id": result.inserted_id})
    return serialize_horse(created_horse)

@api_router.get("/horses", response_model=List[Horse])
async def get_horses(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    horses = await db.horses.find({"user_id": user_id}).sort("name", 1).to_list(1000)
    return [serialize_horse(h) for h in horses]

@api_router.get("/horses/{horse_id}", response_model=Horse)
async def get_horse(horse_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        horse = await db.horses.find_one({"_id": ObjectId(horse_id), "user_id": user_id})
        if not horse:
            raise HTTPException(status_code=404, detail="Horse not found")
        return serialize_horse(horse)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.put("/horses/{horse_id}", response_model=Horse)
async def update_horse(horse_id: str, horse_update: HorseUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in horse_update.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.horses.update_one(
            {"_id": ObjectId(horse_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Horse not found")
        
        updated_horse = await db.horses.find_one({"_id": ObjectId(horse_id)})
        return serialize_horse(updated_horse)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/horses/{horse_id}")
async def delete_horse(horse_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        # Verify horse belongs to user
        horse = await db.horses.find_one({"_id": ObjectId(horse_id), "user_id": user_id})
        if not horse:
            raise HTTPException(status_code=404, detail="Horse not found")
        
        await db.expenses.delete_many({"horse_id": horse_id, "user_id": user_id})
        await db.horse_rider_associations.delete_many({"horse_id": horse_id})
        await db.reminders.delete_many({"entity_type": "horse", "entity_id": horse_id, "user_id": user_id})
        await db.budgets.delete_many({"entity_type": "horse", "entity_id": horse_id})
        await db.palmares.update_many({"horse_id": horse_id}, {"$set": {"horse_id": None}})
        
        result = await db.horses.delete_one({"_id": ObjectId(horse_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Horse not found")
        return {"message": "Horse and associated data deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== RIDER ROUTES ====================

@api_router.post("/riders", response_model=Rider)
async def create_rider(rider: RiderCreate, current_user: dict = Depends(get_current_user)):
    rider_dict = rider.dict()
    rider_dict["user_id"] = str(current_user["_id"])
    rider_dict["created_at"] = datetime.utcnow()
    rider_dict["updated_at"] = datetime.utcnow()
    
    result = await db.riders.insert_one(rider_dict)
    created_rider = await db.riders.find_one({"_id": result.inserted_id})
    return serialize_rider(created_rider)

@api_router.get("/riders", response_model=List[Rider])
async def get_riders(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    riders = await db.riders.find({"user_id": user_id}).sort("name", 1).to_list(1000)
    return [serialize_rider(r) for r in riders]

@api_router.get("/riders/{rider_id}", response_model=Rider)
async def get_rider(rider_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        rider = await db.riders.find_one({"_id": ObjectId(rider_id), "user_id": user_id})
        if not rider:
            raise HTTPException(status_code=404, detail="Rider not found")
        return serialize_rider(rider)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.put("/riders/{rider_id}", response_model=Rider)
async def update_rider(rider_id: str, rider_update: RiderUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in rider_update.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.riders.update_one(
            {"_id": ObjectId(rider_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Rider not found")
        
        updated_rider = await db.riders.find_one({"_id": ObjectId(rider_id)})
        return serialize_rider(updated_rider)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/riders/{rider_id}")
async def delete_rider(rider_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        # Verify rider belongs to user
        rider = await db.riders.find_one({"_id": ObjectId(rider_id), "user_id": user_id})
        if not rider:
            raise HTTPException(status_code=404, detail="Rider not found")
        
        await db.rider_expenses.delete_many({"rider_id": rider_id, "user_id": user_id})
        await db.horse_rider_associations.delete_many({"rider_id": rider_id})
        await db.reminders.delete_many({"entity_type": "rider", "entity_id": rider_id, "user_id": user_id})
        await db.budgets.delete_many({"entity_type": "rider", "entity_id": rider_id})
        await db.palmares.delete_many({"rider_id": rider_id, "user_id": user_id})
        
        result = await db.riders.delete_one({"_id": ObjectId(rider_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Rider not found")
        return {"message": "Rider and associated data deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== SUPPLIER ROUTES ====================

@api_router.post("/suppliers", response_model=Supplier)
async def create_supplier(supplier: SupplierCreate, current_user: dict = Depends(get_current_user)):
    supplier_dict = supplier.dict()
    supplier_dict["user_id"] = str(current_user["_id"])
    supplier_dict["created_at"] = datetime.utcnow()
    supplier_dict["updated_at"] = datetime.utcnow()
    
    result = await db.suppliers.insert_one(supplier_dict)
    created_supplier = await db.suppliers.find_one({"_id": result.inserted_id})
    return serialize_supplier(created_supplier)

@api_router.get("/suppliers", response_model=List[Supplier])
async def get_suppliers(category: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if category:
        query["category"] = category
    suppliers = await db.suppliers.find(query).sort("name", 1).to_list(1000)
    return [serialize_supplier(s) for s in suppliers]

@api_router.get("/suppliers/{supplier_id}", response_model=Supplier)
async def get_supplier(supplier_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        supplier = await db.suppliers.find_one({"_id": ObjectId(supplier_id), "user_id": user_id})
        if not supplier:
            raise HTTPException(status_code=404, detail="Supplier not found")
        return serialize_supplier(supplier)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.put("/suppliers/{supplier_id}", response_model=Supplier)
async def update_supplier(supplier_id: str, supplier_update: SupplierUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in supplier_update.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.suppliers.update_one(
            {"_id": ObjectId(supplier_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Supplier not found")
        
        updated_supplier = await db.suppliers.find_one({"_id": ObjectId(supplier_id)})
        return serialize_supplier(updated_supplier)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/suppliers/{supplier_id}")
async def delete_supplier(supplier_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        supplier = await db.suppliers.find_one({"_id": ObjectId(supplier_id), "user_id": user_id})
        if not supplier:
            raise HTTPException(status_code=404, detail="Supplier not found")
        
        # Remove supplier reference from expenses
        await db.expenses.update_many({"supplier_id": supplier_id, "user_id": user_id}, {"$set": {"supplier_id": None}})
        await db.rider_expenses.update_many({"supplier_id": supplier_id, "user_id": user_id}, {"$set": {"supplier_id": None}})
        
        result = await db.suppliers.delete_one({"_id": ObjectId(supplier_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Supplier not found")
        return {"message": "Supplier deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/suppliers/{supplier_id}/report")
async def get_supplier_report(
    supplier_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get expense report for a specific supplier"""
    user_id = str(current_user["_id"])
    try:
        supplier = await db.suppliers.find_one({"_id": ObjectId(supplier_id), "user_id": user_id})
        if not supplier:
            raise HTTPException(status_code=404, detail="Supplier not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid supplier_id")
    
    query = {"supplier_id": supplier_id, "user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    # Get horse expenses
    horse_expenses = await db.expenses.find(query).sort("date", -1).to_list(10000)
    
    # Get rider expenses
    rider_expenses = await db.rider_expenses.find(query).sort("date", -1).to_list(10000)
    
    horse_total = sum(e.get("amount", 0) for e in horse_expenses)
    rider_total = sum(e.get("amount", 0) for e in rider_expenses)
    
    return {
        "supplier": serialize_supplier(supplier),
        "horse_expenses": [serialize_expense(e) for e in horse_expenses],
        "rider_expenses": [serialize_rider_expense(e) for e in rider_expenses],
        "horse_total": horse_total,
        "rider_total": rider_total,
        "total": horse_total + rider_total,
        "horse_count": len(horse_expenses),
        "rider_count": len(rider_expenses),
        "total_count": len(horse_expenses) + len(rider_expenses),
        "start_date": start_date,
        "end_date": end_date
    }

@api_router.get("/reports/suppliers")
async def get_suppliers_report(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get report of all suppliers with their expenses"""
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    suppliers = await db.suppliers.find({"user_id": user_id}).to_list(1000)
    supplier_map = {str(s["_id"]): serialize_supplier(s) for s in suppliers}
    
    # Get all expenses with supplier_id
    horse_expenses = await db.expenses.find({**query, "supplier_id": {"$ne": None}}).to_list(10000)
    rider_expenses = await db.rider_expenses.find({**query, "supplier_id": {"$ne": None}}).to_list(10000)
    
    by_supplier = {}
    
    for exp in horse_expenses:
        sid = exp.get("supplier_id")
        if sid:
            if sid not in by_supplier:
                by_supplier[sid] = {
                    "supplier": supplier_map.get(sid, {"id": sid, "name": "Desconocido"}),
                    "total": 0,
                    "count": 0
                }
            by_supplier[sid]["total"] += exp.get("amount", 0)
            by_supplier[sid]["count"] += 1
    
    for exp in rider_expenses:
        sid = exp.get("supplier_id")
        if sid:
            if sid not in by_supplier:
                by_supplier[sid] = {
                    "supplier": supplier_map.get(sid, {"id": sid, "name": "Desconocido"}),
                    "total": 0,
                    "count": 0
                }
            by_supplier[sid]["total"] += exp.get("amount", 0)
            by_supplier[sid]["count"] += 1
    
    result = sorted(by_supplier.values(), key=lambda x: x["total"], reverse=True)
    
    return {
        "suppliers": result,
        "grand_total": sum(s["total"] for s in result),
        "total_count": sum(s["count"] for s in result),
        "start_date": start_date,
        "end_date": end_date
    }

# ==================== HORSE-RIDER ASSOCIATION ROUTES ====================

@api_router.post("/associations")
async def create_association(assoc: HorseRiderAssociation, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    
    # Verify both horse and rider belong to user
    horse = await db.horses.find_one({"_id": ObjectId(assoc.horse_id), "user_id": user_id})
    rider = await db.riders.find_one({"_id": ObjectId(assoc.rider_id), "user_id": user_id})
    
    if not horse:
        raise HTTPException(status_code=404, detail="Horse not found")
    if not rider:
        raise HTTPException(status_code=404, detail="Rider not found")
    
    existing = await db.horse_rider_associations.find_one({
        "horse_id": assoc.horse_id,
        "rider_id": assoc.rider_id
    })
    if existing:
        raise HTTPException(status_code=400, detail="Association already exists")
    
    assoc_dict = assoc.dict()
    assoc_dict["user_id"] = user_id
    assoc_dict["created_at"] = datetime.utcnow()
    await db.horse_rider_associations.insert_one(assoc_dict)
    return {"message": "Association created successfully"}

@api_router.delete("/associations")
async def delete_association(horse_id: str, rider_id: str, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    result = await db.horse_rider_associations.delete_one({
        "horse_id": horse_id,
        "rider_id": rider_id,
        "user_id": user_id
    })
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Association not found")
    return {"message": "Association deleted successfully"}

@api_router.get("/horses/{horse_id}/riders")
async def get_horse_riders(horse_id: str, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    # Verify horse belongs to user
    horse = await db.horses.find_one({"_id": ObjectId(horse_id), "user_id": user_id})
    if not horse:
        raise HTTPException(status_code=404, detail="Horse not found")
    
    associations = await db.horse_rider_associations.find({"horse_id": horse_id}).to_list(100)
    rider_ids = [a["rider_id"] for a in associations]
    
    # Bulk query instead of N+1
    if rider_ids:
        rider_object_ids = [ObjectId(rid) for rid in rider_ids if ObjectId.is_valid(rid)]
        riders_cursor = await db.riders.find({
            "_id": {"$in": rider_object_ids},
            "user_id": user_id
        }).to_list(100)
        riders = [serialize_rider(r) for r in riders_cursor]
    else:
        riders = []
    return riders

@api_router.get("/riders/{rider_id}/horses")
async def get_rider_horses(rider_id: str, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    # Verify rider belongs to user
    rider = await db.riders.find_one({"_id": ObjectId(rider_id), "user_id": user_id})
    if not rider:
        raise HTTPException(status_code=404, detail="Rider not found")
    
    associations = await db.horse_rider_associations.find({"rider_id": rider_id}).to_list(100)
    horse_ids = [a["horse_id"] for a in associations]
    
    # Bulk query instead of N+1
    if horse_ids:
        horse_object_ids = [ObjectId(hid) for hid in horse_ids if ObjectId.is_valid(hid)]
        horses_cursor = await db.horses.find({
            "_id": {"$in": horse_object_ids},
            "user_id": user_id
        }).to_list(100)
        horses = [serialize_horse(h) for h in horses_cursor]
    else:
        horses = []
    return horses

# ==================== PALMARES ROUTES ====================

@api_router.post("/palmares", response_model=Palmares)
async def create_palmares(palmares: PalmaresCreate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    try:
        rider = await db.riders.find_one({"_id": ObjectId(palmares.rider_id), "user_id": user_id})
        if not rider:
            raise HTTPException(status_code=404, detail="Rider not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid rider_id")
    
    palmares_dict = palmares.dict()
    palmares_dict["user_id"] = user_id
    palmares_dict["created_at"] = datetime.utcnow()
    palmares_dict["updated_at"] = datetime.utcnow()
    
    result = await db.palmares.insert_one(palmares_dict)
    created_palmares = await db.palmares.find_one({"_id": result.inserted_id})
    return serialize_palmares(created_palmares)

@api_router.get("/palmares")
async def get_all_palmares(
    rider_id: Optional[str] = None,
    discipline: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if rider_id:
        query["rider_id"] = rider_id
    if discipline:
        query["discipline"] = discipline
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    palmares_list = await db.palmares.find(query).sort("date", -1).to_list(1000)
    return [serialize_palmares(p) for p in palmares_list]

@api_router.get("/riders/{rider_id}/palmares")
async def get_rider_palmares(rider_id: str, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    palmares_list = await db.palmares.find({"rider_id": rider_id, "user_id": user_id}).sort("date", -1).to_list(1000)
    return [serialize_palmares(p) for p in palmares_list]

@api_router.get("/palmares/{palmares_id}")
async def get_palmares(palmares_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        palmares = await db.palmares.find_one({"_id": ObjectId(palmares_id), "user_id": user_id})
        if not palmares:
            raise HTTPException(status_code=404, detail="Palmares not found")
        return serialize_palmares(palmares)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.put("/palmares/{palmares_id}")
async def update_palmares(palmares_id: str, palmares_update: PalmaresUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in palmares_update.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.palmares.update_one(
            {"_id": ObjectId(palmares_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Palmares not found")
        
        updated_palmares = await db.palmares.find_one({"_id": ObjectId(palmares_id)})
        return serialize_palmares(updated_palmares)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/palmares/{palmares_id}")
async def delete_palmares(palmares_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        result = await db.palmares.delete_one({"_id": ObjectId(palmares_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Palmares not found")
        return {"message": "Palmares deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== COMPETITION ROUTES ====================

@api_router.post("/competitions", response_model=Competition)
async def create_competition(competition: CompetitionCreate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    competition_dict = competition.dict()
    competition_dict["user_id"] = user_id
    competition_dict["created_at"] = datetime.utcnow()
    competition_dict["updated_at"] = datetime.utcnow()
    
    result = await db.competitions.insert_one(competition_dict)
    created_competition = await db.competitions.find_one({"_id": result.inserted_id})
    
    # Create automatic reminders for the competition
    await create_competition_reminders(created_competition, user_id)
    
    return serialize_competition(created_competition)

async def create_competition_reminders(competition: dict, user_id: str):
    """Create automatic reminders for a competition"""
    comp_date = competition.get("date", "")
    comp_name = competition.get("name", "")
    comp_id = str(competition["_id"])
    
    try:
        date_obj = datetime.strptime(comp_date, "%Y-%m-%d")
        
        # Reminder 1 week before
        week_before = date_obj - timedelta(days=7)
        if week_before > datetime.now():
            await db.reminders.insert_one({
                "user_id": user_id,
                "title": f"Concurso en 1 semana: {comp_name}",
                "description": f"Preparar todo para el concurso en {competition.get('city', '')}",
                "reminder_date": week_before.strftime("%Y-%m-%d"),
                "reminder_time": "18:00",
                "entity_type": "competition",
                "entity_id": comp_id,
                "competition_id": comp_id,
                "is_automatic": True,
                "is_completed": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            })
        
        # Reminder 3 days before
        three_days = date_obj - timedelta(days=3)
        if three_days > datetime.now():
            await db.reminders.insert_one({
                "user_id": user_id,
                "title": f"Concurso en 3 días: {comp_name}",
                "description": f"Verificar inscripciones y preparativos",
                "reminder_date": three_days.strftime("%Y-%m-%d"),
                "reminder_time": "18:00",
                "entity_type": "competition",
                "entity_id": comp_id,
                "competition_id": comp_id,
                "is_automatic": True,
                "is_completed": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            })
        
        # Reminder day before
        day_before = date_obj - timedelta(days=1)
        if day_before > datetime.now():
            await db.reminders.insert_one({
                "user_id": user_id,
                "title": f"Mañana: {comp_name}",
                "description": f"Preparar transporte y equipamiento para {competition.get('city', '')}",
                "reminder_date": day_before.strftime("%Y-%m-%d"),
                "reminder_time": "18:00",
                "entity_type": "competition",
                "entity_id": comp_id,
                "competition_id": comp_id,
                "is_automatic": True,
                "is_completed": False,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            })
        
        # Entry deadline reminder
        entry_deadline = competition.get("entry_deadline")
        if entry_deadline:
            deadline_obj = datetime.strptime(entry_deadline, "%Y-%m-%d")
            deadline_reminder = deadline_obj - timedelta(days=2)
            if deadline_reminder > datetime.now():
                await db.reminders.insert_one({
                    "user_id": user_id,
                    "title": f"Inscripción cierra pronto: {comp_name}",
                    "description": f"Fecha límite de inscripción: {entry_deadline}",
                    "reminder_date": deadline_reminder.strftime("%Y-%m-%d"),
                    "reminder_time": "10:00",
                    "entity_type": "competition",
                    "entity_id": comp_id,
                    "competition_id": comp_id,
                    "is_automatic": True,
                    "is_completed": False,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                })
    except:
        pass

@api_router.get("/competitions")
async def get_competitions(
    discipline: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    upcoming: bool = False,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    
    if discipline:
        query["discipline"] = discipline
    
    if upcoming:
        today = datetime.now().strftime("%Y-%m-%d")
        query["date"] = {"$gte": today}
    elif start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    competitions = await db.competitions.find(query).sort("date", 1).to_list(1000)
    return [serialize_competition(c) for c in competitions]

@api_router.get("/competitions/{competition_id}")
async def get_competition(competition_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        competition = await db.competitions.find_one({"_id": ObjectId(competition_id), "user_id": user_id})
        if not competition:
            raise HTTPException(status_code=404, detail="Competition not found")
        return serialize_competition(competition)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.put("/competitions/{competition_id}")
async def update_competition(competition_id: str, competition_update: CompetitionUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in competition_update.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.competitions.update_one(
            {"_id": ObjectId(competition_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Competition not found")
        
        updated_competition = await db.competitions.find_one({"_id": ObjectId(competition_id)})
        return serialize_competition(updated_competition)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/competitions/{competition_id}")
async def delete_competition(competition_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        # Delete associated reminders
        await db.reminders.delete_many({"competition_id": competition_id, "user_id": user_id})
        
        result = await db.competitions.delete_one({"_id": ObjectId(competition_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Competition not found")
        return {"message": "Competition and associated reminders deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== HORSE EXPENSE ROUTES ====================

@api_router.post("/expenses", response_model=Expense)
async def create_expense(expense: ExpenseCreate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    try:
        horse = await db.horses.find_one({"_id": ObjectId(expense.horse_id), "user_id": user_id})
        if not horse:
            raise HTTPException(status_code=404, detail="Horse not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid horse_id")
    
    if expense.category not in HORSE_EXPENSE_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {HORSE_EXPENSE_CATEGORIES}")
    
    expense_dict = expense.dict()
    expense_dict["user_id"] = user_id
    expense_dict["created_at"] = datetime.utcnow()
    expense_dict["updated_at"] = datetime.utcnow()
    
    result = await db.expenses.insert_one(expense_dict)
    created_expense = await db.expenses.find_one({"_id": result.inserted_id})
    
    # Create automatic reminder only if create_reminder is True
    if expense_dict.get("create_reminder", True):
        await create_automatic_reminder_suggestion(expense_dict, "horse", user_id)
    
    # Handle recurring expense - create monthly reminder
    if expense_dict.get("is_recurring", False):
        try:
            expense_date = datetime.strptime(expense_dict.get("date", ""), "%Y-%m-%d")
            next_month = expense_date + timedelta(days=30)
            category_name = HORSE_CATEGORY_NAMES.get(expense_dict["category"], expense_dict["category"])
            horse_name = horse.get("name", "")
            
            recurring_reminder = {
                "user_id": user_id,
                "title": f"Pago mensual: {category_name} - {horse_name}",
                "description": f"Gasto recurrente de {expense_dict['amount']}€. Último pago: {expense_dict['date']}",
                "reminder_date": next_month.strftime("%Y-%m-%d"),
                "reminder_time": "18:00",
                "entity_type": "horse",
                "entity_id": expense.horse_id,
                "category": expense_dict["category"],
                "is_automatic": True,
                "is_completed": False,
                "priority": "importante",
                "interval_days": 30,
                "is_recurring_payment": True,
                "recurring_amount": expense_dict["amount"],
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            await db.reminders.insert_one(recurring_reminder)
        except Exception as e:
            print(f"Error creating recurring reminder: {e}")
    
    return serialize_expense(created_expense)

@api_router.get("/expenses", response_model=List[Expense])
async def get_expenses(
    horse_id: Optional[str] = None,
    category: Optional[str] = None,
    supplier_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    
    if horse_id:
        query["horse_id"] = horse_id
    if category:
        query["category"] = category
    if supplier_id:
        query["supplier_id"] = supplier_id
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    expenses = await db.expenses.find(query).sort("date", -1).to_list(limit)
    return [serialize_expense(e) for e in expenses]

@api_router.get("/expenses/{expense_id}", response_model=Expense)
async def get_expense(expense_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        expense = await db.expenses.find_one({"_id": ObjectId(expense_id), "user_id": user_id})
        if not expense:
            raise HTTPException(status_code=404, detail="Expense not found")
        return serialize_expense(expense)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.put("/expenses/{expense_id}", response_model=Expense)
async def update_expense(expense_id: str, expense_update: ExpenseUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in expense_update.dict().items() if v is not None}
        
        if "category" in update_data and update_data["category"] not in HORSE_EXPENSE_CATEGORIES:
            raise HTTPException(status_code=400, detail=f"Invalid category")
        
        if "horse_id" in update_data:
            horse = await db.horses.find_one({"_id": ObjectId(update_data["horse_id"]), "user_id": user_id})
            if not horse:
                raise HTTPException(status_code=404, detail="Horse not found")
        
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.expenses.update_one(
            {"_id": ObjectId(expense_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Expense not found")
        
        updated_expense = await db.expenses.find_one({"_id": ObjectId(expense_id)})
        return serialize_expense(updated_expense)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/expenses/{expense_id}")
async def delete_expense(expense_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        result = await db.expenses.delete_one({"_id": ObjectId(expense_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Expense not found")
        return {"message": "Expense deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== RIDER EXPENSE ROUTES ====================

@api_router.post("/rider-expenses", response_model=RiderExpense)
async def create_rider_expense(expense: RiderExpenseCreate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    try:
        rider = await db.riders.find_one({"_id": ObjectId(expense.rider_id), "user_id": user_id})
        if not rider:
            raise HTTPException(status_code=404, detail="Rider not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid rider_id")
    
    if expense.category not in RIDER_EXPENSE_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Invalid category. Must be one of: {RIDER_EXPENSE_CATEGORIES}")
    
    expense_dict = expense.dict()
    expense_dict["user_id"] = user_id
    expense_dict["created_at"] = datetime.utcnow()
    expense_dict["updated_at"] = datetime.utcnow()
    
    result = await db.rider_expenses.insert_one(expense_dict)
    created_expense = await db.rider_expenses.find_one({"_id": result.inserted_id})
    
    await create_automatic_reminder_suggestion(expense_dict, "rider", user_id)
    
    return serialize_rider_expense(created_expense)

@api_router.get("/rider-expenses", response_model=List[RiderExpense])
async def get_rider_expenses(
    rider_id: Optional[str] = None,
    category: Optional[str] = None,
    supplier_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    
    if rider_id:
        query["rider_id"] = rider_id
    if category:
        query["category"] = category
    if supplier_id:
        query["supplier_id"] = supplier_id
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    expenses = await db.rider_expenses.find(query).sort("date", -1).to_list(limit)
    return [serialize_rider_expense(e) for e in expenses]

@api_router.get("/rider-expenses/{expense_id}", response_model=RiderExpense)
async def get_rider_expense(expense_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        expense = await db.rider_expenses.find_one({"_id": ObjectId(expense_id), "user_id": user_id})
        if not expense:
            raise HTTPException(status_code=404, detail="Expense not found")
        return serialize_rider_expense(expense)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.put("/rider-expenses/{expense_id}", response_model=RiderExpense)
async def update_rider_expense(expense_id: str, expense_update: RiderExpenseUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in expense_update.dict().items() if v is not None}
        
        if "category" in update_data and update_data["category"] not in RIDER_EXPENSE_CATEGORIES:
            raise HTTPException(status_code=400, detail=f"Invalid category")
        
        if "rider_id" in update_data:
            rider = await db.riders.find_one({"_id": ObjectId(update_data["rider_id"]), "user_id": user_id})
            if not rider:
                raise HTTPException(status_code=404, detail="Rider not found")
        
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.rider_expenses.update_one(
            {"_id": ObjectId(expense_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Expense not found")
        
        updated_expense = await db.rider_expenses.find_one({"_id": ObjectId(expense_id)})
        return serialize_rider_expense(updated_expense)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/rider-expenses/{expense_id}")
async def delete_rider_expense(expense_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        result = await db.rider_expenses.delete_one({"_id": ObjectId(expense_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Expense not found")
        return {"message": "Expense deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== REMINDER ROUTES ====================

# Intervalos por defecto para avisos automáticos (en días)
DEFAULT_REMINDER_INTERVALS = {
    # Caballos
    "herrador": 45,           # 6-7 semanas
    "veterinario": 365,       # Revisión anual
    "dentista": 365,          # Revisión anual
    "vacunas": 180,           # 6 meses (configurable por tipo)
    "desparasitacion": 90,    # 3 meses
    "fisioterapia": 30,       # Mensual si compite
    # Jinetes
    "licencias": 365,
    "seguros": 365,
    "equipamiento": 365,      # Revisión anual equipo
    # Documentación
    "pasaporte": 365,
    "itv_remolque": 365,
}

# Categorías que generan aviso automático
AUTO_REMINDER_CATEGORIES = list(DEFAULT_REMINDER_INTERVALS.keys())

# Niveles de prioridad
REMINDER_PRIORITY = {
    "info": 1,
    "importante": 2, 
    "urgente": 3
}

async def get_entity_interval(user_id: str, entity_type: str, entity_id: str, category: str) -> int:
    """Obtiene el intervalo personalizado para una entidad o usa el default"""
    if entity_id:
        # Buscar configuración personalizada del caballo/jinete
        collection = db.horses if entity_type == "horse" else db.riders
        entity = await collection.find_one({"_id": ObjectId(entity_id), "user_id": user_id})
        if entity:
            custom_intervals = entity.get("reminder_intervals", {})
            if category in custom_intervals:
                return custom_intervals[category]
    return DEFAULT_REMINDER_INTERVALS.get(category, 30)

async def create_automatic_reminder_suggestion(expense: dict, entity_type: str, user_id: str):
    """Crea aviso automático basado en el gasto registrado"""
    category = expense.get("category")
    if category not in AUTO_REMINDER_CATEGORIES:
        return
    
    entity_id = expense.get("horse_id") if entity_type == "horse" else expense.get("rider_id")
    interval = await get_entity_interval(user_id, entity_type, entity_id, category)
    expense_date = expense.get("date", "")
    
    try:
        date_obj = datetime.strptime(expense_date, "%Y-%m-%d")
        next_date = date_obj + timedelta(days=interval)
        
        # No crear si ya existe uno igual
        existing = await db.reminders.find_one({
            "user_id": user_id,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "category": category,
            "reminder_date": next_date.strftime("%Y-%m-%d"),
            "is_automatic": True
        })
        
        if not existing:
            category_name = HORSE_CATEGORY_NAMES.get(category, category) if entity_type == "horse" else RIDER_CATEGORY_NAMES.get(category, category)
            
            # Obtener nombre de la entidad
            entity_name = ""
            if entity_id:
                collection = db.horses if entity_type == "horse" else db.riders
                entity = await collection.find_one({"_id": ObjectId(entity_id)})
                if entity:
                    entity_name = entity.get("name", "")
            
            # Determinar prioridad según categoría
            priority = "importante" if category in ["veterinario", "vacunas", "licencias", "seguros"] else "info"
            
            reminder = {
                "user_id": user_id,
                "title": f"{category_name}: {entity_name}" if entity_name else f"Recordatorio: {category_name}",
                "description": f"Última vez: {expense_date}. Próxima: {next_date.strftime('%d/%m/%Y')}",
                "reminder_date": next_date.strftime("%Y-%m-%d"),
                "reminder_time": "18:00",
                "entity_type": entity_type,
                "entity_id": entity_id,
                "category": category,
                "is_automatic": True,
                "is_completed": False,
                "priority": priority,
                "interval_days": interval,  # Guardar intervalo para reprogramar
                "last_completed_date": expense_date,  # Fecha del último
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }
            await db.reminders.insert_one(reminder)
            
            # Crear preaviso 7 días antes si el intervalo es > 30 días
            if interval > 30:
                preaviso_date = next_date - timedelta(days=7)
                if preaviso_date > datetime.now():
                    preaviso = {
                        "user_id": user_id,
                        "title": f"Próximamente: {category_name} - {entity_name}" if entity_name else f"Próximamente: {category_name}",
                        "description": f"En 7 días toca {category_name.lower()}",
                        "reminder_date": preaviso_date.strftime("%Y-%m-%d"),
                        "reminder_time": "18:00",
                        "entity_type": entity_type,
                        "entity_id": entity_id,
                        "category": category,
                        "is_automatic": True,
                        "is_completed": False,
                        "priority": "info",
                        "is_preaviso": True,
                        "parent_reminder_date": next_date.strftime("%Y-%m-%d"),
                        "created_at": datetime.utcnow(),
                        "updated_at": datetime.utcnow()
                    }
                    await db.reminders.insert_one(preaviso)
    except Exception as e:
        print(f"Error creating automatic reminder: {e}")
        pass

@api_router.post("/reminders", response_model=Reminder)
async def create_reminder(reminder: ReminderCreate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    reminder_dict = reminder.dict()
    reminder_dict["user_id"] = user_id
    reminder_dict["created_at"] = datetime.utcnow()
    reminder_dict["updated_at"] = datetime.utcnow()
    
    result = await db.reminders.insert_one(reminder_dict)
    created_reminder = await db.reminders.find_one({"_id": result.inserted_id})
    return serialize_reminder(created_reminder)

@api_router.get("/reminders", response_model=List[Reminder])
async def get_reminders(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    is_completed: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    
    if entity_type:
        query["entity_type"] = entity_type
    if entity_id:
        query["entity_id"] = entity_id
    if is_completed is not None:
        query["is_completed"] = is_completed
    if start_date or end_date:
        query["reminder_date"] = {}
        if start_date:
            query["reminder_date"]["$gte"] = start_date
        if end_date:
            query["reminder_date"]["$lte"] = end_date
    
    reminders = await db.reminders.find(query).sort("reminder_date", 1).to_list(1000)
    return [serialize_reminder(r) for r in reminders]

@api_router.get("/reminders/upcoming")
async def get_upcoming_reminders(days: int = 7, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    today = datetime.now().strftime("%Y-%m-%d")
    end_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    
    reminders = await db.reminders.find({
        "user_id": user_id,
        "reminder_date": {"$gte": today, "$lte": end_date},
        "is_completed": False
    }).sort("reminder_date", 1).to_list(100)
    
    return [serialize_reminder(r) for r in reminders]

@api_router.post("/reminders/{reminder_id}/complete")
async def complete_and_reschedule_reminder(
    reminder_id: str, 
    reschedule: bool = True,
    current_user: dict = Depends(get_current_user)
):
    """
    Marca un aviso como completado y opcionalmente crea el siguiente automáticamente.
    - reschedule=True: Crea el próximo aviso según el intervalo configurado
    - reschedule=False: Solo marca como completado sin reprogramar
    """
    try:
        user_id = str(current_user["_id"])
        reminder = await db.reminders.find_one({"_id": ObjectId(reminder_id), "user_id": user_id})
        
        if not reminder:
            raise HTTPException(status_code=404, detail="Reminder not found")
        
        # Marcar como completado
        today = datetime.now().strftime("%Y-%m-%d")
        await db.reminders.update_one(
            {"_id": ObjectId(reminder_id)},
            {"$set": {
                "is_completed": True,
                "completed_date": today,
                "updated_at": datetime.utcnow()
            }}
        )
        
        # Eliminar preavisos asociados si existen
        if reminder.get("is_automatic"):
            await db.reminders.delete_many({
                "user_id": user_id,
                "is_preaviso": True,
                "parent_reminder_date": reminder.get("reminder_date"),
                "entity_id": reminder.get("entity_id"),
                "category": reminder.get("category")
            })
        
        next_reminder = None
        
        # Reprogramar si es automático y tiene categoría con intervalo
        if reschedule and reminder.get("category"):
            category = reminder.get("category")
            entity_type = reminder.get("entity_type", "horse")
            entity_id = reminder.get("entity_id")
            
            # Obtener intervalo (personalizado o default)
            interval = reminder.get("interval_days")
            if not interval:
                interval = await get_entity_interval(user_id, entity_type, entity_id, category)
            
            if interval:
                next_date = datetime.strptime(today, "%Y-%m-%d") + timedelta(days=interval)
                
                # Obtener nombre de categoría y entidad
                category_name = HORSE_CATEGORY_NAMES.get(category, category) if entity_type == "horse" else RIDER_CATEGORY_NAMES.get(category, category)
                entity_name = ""
                if entity_id:
                    collection = db.horses if entity_type == "horse" else db.riders
                    entity = await collection.find_one({"_id": ObjectId(entity_id)})
                    if entity:
                        entity_name = entity.get("name", "")
                
                # Crear siguiente aviso
                new_reminder = {
                    "user_id": user_id,
                    "title": f"{category_name}: {entity_name}" if entity_name else f"Recordatorio: {category_name}",
                    "description": f"Última vez: {today}. Próxima: {next_date.strftime('%d/%m/%Y')}",
                    "reminder_date": next_date.strftime("%Y-%m-%d"),
                    "reminder_time": reminder.get("reminder_time", "18:00"),
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "category": category,
                    "is_automatic": True,
                    "is_completed": False,
                    "priority": reminder.get("priority", "info"),
                    "interval_days": interval,
                    "last_completed_date": today,
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
                result = await db.reminders.insert_one(new_reminder)
                next_reminder = await db.reminders.find_one({"_id": result.inserted_id})
                
                # Crear preaviso si el intervalo es largo
                if interval > 30:
                    preaviso_date = next_date - timedelta(days=7)
                    if preaviso_date > datetime.now():
                        preaviso = {
                            "user_id": user_id,
                            "title": f"Próximamente: {category_name} - {entity_name}" if entity_name else f"Próximamente: {category_name}",
                            "description": f"En 7 días toca {category_name.lower()}",
                            "reminder_date": preaviso_date.strftime("%Y-%m-%d"),
                            "reminder_time": "18:00",
                            "entity_type": entity_type,
                            "entity_id": entity_id,
                            "category": category,
                            "is_automatic": True,
                            "is_completed": False,
                            "priority": "info",
                            "is_preaviso": True,
                            "parent_reminder_date": next_date.strftime("%Y-%m-%d"),
                            "created_at": datetime.utcnow(),
                            "updated_at": datetime.utcnow()
                        }
                        await db.reminders.insert_one(preaviso)
        
        return {
            "message": "Reminder completed successfully",
            "completed_id": reminder_id,
            "next_reminder": serialize_reminder(next_reminder) if next_reminder else None
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.get("/reminders/intervals")
async def get_reminder_intervals(current_user: dict = Depends(get_current_user)):
    """Obtiene los intervalos por defecto para avisos automáticos"""
    return {
        "default_intervals": DEFAULT_REMINDER_INTERVALS,
        "categories": AUTO_REMINDER_CATEGORIES
    }

@api_router.put("/reminders/{reminder_id}", response_model=Reminder)
async def update_reminder(reminder_id: str, reminder_update: ReminderUpdate, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        update_data = {k: v for k, v in reminder_update.dict().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow()
        
        result = await db.reminders.update_one(
            {"_id": ObjectId(reminder_id), "user_id": user_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Reminder not found")
        
        updated_reminder = await db.reminders.find_one({"_id": ObjectId(reminder_id)})
        return serialize_reminder(updated_reminder)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@api_router.delete("/reminders/{reminder_id}")
async def delete_reminder(reminder_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        result = await db.reminders.delete_one({"_id": ObjectId(reminder_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Reminder not found")
        return {"message": "Reminder deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== BUDGET ROUTES ====================

@api_router.post("/budgets", response_model=Budget)
async def create_or_update_budget(budget: BudgetCreate, current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    query = {
        "user_id": user_id,
        "entity_type": budget.entity_type,
        "entity_id": budget.entity_id,
        "category": budget.category,
        "month": budget.month,
        "year": budget.year
    }
    
    existing = await db.budgets.find_one(query)
    
    if existing:
        await db.budgets.update_one(
            {"_id": existing["_id"]},
            {"$set": {"amount": budget.amount, "updated_at": datetime.utcnow()}}
        )
        updated = await db.budgets.find_one({"_id": existing["_id"]})
        return serialize_budget(updated)
    else:
        budget_dict = budget.dict()
        budget_dict["user_id"] = user_id
        budget_dict["created_at"] = datetime.utcnow()
        budget_dict["updated_at"] = datetime.utcnow()
        
        result = await db.budgets.insert_one(budget_dict)
        created = await db.budgets.find_one({"_id": result.inserted_id})
        return serialize_budget(created)

@api_router.get("/budgets")
async def get_budgets(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    month: Optional[int] = None,
    year: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if entity_type:
        query["entity_type"] = entity_type
    if entity_id:
        query["entity_id"] = entity_id
    if month:
        query["month"] = month
    if year:
        query["year"] = year
    
    budgets = await db.budgets.find(query).to_list(1000)
    return [serialize_budget(b) for b in budgets]

@api_router.get("/budgets/status")
async def get_budget_status(
    entity_type: str = "horse",
    month: int = Query(default=datetime.now().month),
    year: int = Query(default=datetime.now().year),
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    budgets = await db.budgets.find({
        "user_id": user_id,
        "entity_type": entity_type,
        "month": month,
        "year": year
    }).to_list(1000)
    
    start_date = f"{year}-{month:02d}-01"
    if month == 12:
        end_date = f"{year + 1}-01-01"
    else:
        end_date = f"{year}-{month + 1:02d}-01"
    
    if entity_type == "horse":
        expenses = await db.expenses.find({
            "user_id": user_id,
            "date": {"$gte": start_date, "$lt": end_date}
        }).to_list(10000)
    else:
        expenses = await db.rider_expenses.find({
            "user_id": user_id,
            "date": {"$gte": start_date, "$lt": end_date}
        }).to_list(10000)
    
    actual_by_entity = {}
    actual_by_category = {}
    
    id_field = "horse_id" if entity_type == "horse" else "rider_id"
    
    for exp in expenses:
        eid = exp.get(id_field)
        cat = exp.get("category")
        amount = exp.get("amount", 0)
        
        if eid not in actual_by_entity:
            actual_by_entity[eid] = {"total": 0, "by_category": {}}
        actual_by_entity[eid]["total"] += amount
        
        if cat not in actual_by_entity[eid]["by_category"]:
            actual_by_entity[eid]["by_category"][cat] = 0
        actual_by_entity[eid]["by_category"][cat] += amount
        
        if cat not in actual_by_category:
            actual_by_category[cat] = 0
        actual_by_category[cat] += amount
    
    status = []
    for budget in budgets:
        entity_id = budget.get("entity_id")
        category = budget.get("category")
        budgeted = budget.get("amount", 0)
        
        if entity_id and category:
            actual = actual_by_entity.get(entity_id, {}).get("by_category", {}).get(category, 0)
        elif entity_id:
            actual = actual_by_entity.get(entity_id, {}).get("total", 0)
        elif category:
            actual = actual_by_category.get(category, 0)
        else:
            actual = sum(e.get("total", 0) for e in actual_by_entity.values())
        
        percentage = (actual / budgeted * 100) if budgeted > 0 else 0
        
        status.append({
            "budget": serialize_budget(budget),
            "actual": actual,
            "remaining": budgeted - actual,
            "percentage": round(percentage, 1),
            "over_budget": actual > budgeted
        })
    
    return {
        "month": month,
        "year": year,
        "entity_type": entity_type,
        "status": status,
        "total_budgeted": sum(b.get("amount", 0) for b in budgets),
        "total_actual": sum(s["actual"] for s in status)
    }

@api_router.delete("/budgets/{budget_id}")
async def delete_budget(budget_id: str, current_user: dict = Depends(get_current_user)):
    try:
        user_id = str(current_user["_id"])
        result = await db.budgets.delete_one({"_id": ObjectId(budget_id), "user_id": user_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Budget not found")
        return {"message": "Budget deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ==================== REPORT ROUTES ====================

@api_router.get("/reports/summary")
async def get_expense_summary(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    entity_type: str = "horse",
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    collection = db.expenses if entity_type == "horse" else db.rider_expenses
    categories = HORSE_EXPENSE_CATEGORIES if entity_type == "horse" else RIDER_EXPENSE_CATEGORIES
    category_names = HORSE_CATEGORY_NAMES if entity_type == "horse" else RIDER_CATEGORY_NAMES
    
    expenses = await collection.find(query).to_list(10000)
    
    total = sum(e.get("amount", 0) for e in expenses)
    count = len(expenses)
    
    by_category = {}
    for cat in categories:
        cat_expenses = [e for e in expenses if e.get("category") == cat]
        by_category[cat] = {
            "total": sum(e.get("amount", 0) for e in cat_expenses),
            "count": len(cat_expenses),
            "name": category_names.get(cat, cat)
        }
    
    return {
        "total": total,
        "count": count,
        "by_category": by_category,
        "start_date": start_date,
        "end_date": end_date,
        "entity_type": entity_type
    }

@api_router.get("/reports/by-horse")
async def get_expenses_by_horse(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    expenses = await db.expenses.find(query).to_list(10000)
    horses = await db.horses.find({"user_id": user_id}).to_list(1000)
    horse_map = {str(h["_id"]): h.get("name", "Unknown") for h in horses}
    
    by_horse = {}
    for expense in expenses:
        horse_id = expense.get("horse_id", "")
        if horse_id not in by_horse:
            by_horse[horse_id] = {
                "horse_id": horse_id,
                "horse_name": horse_map.get(horse_id, "Unknown"),
                "total": 0,
                "count": 0,
                "by_category": {cat: {"total": 0, "count": 0, "name": HORSE_CATEGORY_NAMES.get(cat, cat)} for cat in HORSE_EXPENSE_CATEGORIES}
            }
        
        by_horse[horse_id]["total"] += expense.get("amount", 0)
        by_horse[horse_id]["count"] += 1
        
        cat = expense.get("category", "otros")
        if cat in by_horse[horse_id]["by_category"]:
            by_horse[horse_id]["by_category"][cat]["total"] += expense.get("amount", 0)
            by_horse[horse_id]["by_category"][cat]["count"] += 1
    
    result = sorted(by_horse.values(), key=lambda x: x["total"], reverse=True)
    
    return {
        "horses": result,
        "start_date": start_date,
        "end_date": end_date,
        "grand_total": sum(h["total"] for h in result)
    }

@api_router.get("/reports/by-rider")
async def get_expenses_by_rider(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    expenses = await db.rider_expenses.find(query).to_list(10000)
    riders = await db.riders.find({"user_id": user_id}).to_list(1000)
    rider_map = {str(r["_id"]): r.get("name", "Unknown") for r in riders}
    
    by_rider = {}
    for expense in expenses:
        rider_id = expense.get("rider_id", "")
        if rider_id not in by_rider:
            by_rider[rider_id] = {
                "rider_id": rider_id,
                "rider_name": rider_map.get(rider_id, "Unknown"),
                "total": 0,
                "count": 0,
                "by_category": {cat: {"total": 0, "count": 0, "name": RIDER_CATEGORY_NAMES.get(cat, cat)} for cat in RIDER_EXPENSE_CATEGORIES}
            }
        
        by_rider[rider_id]["total"] += expense.get("amount", 0)
        by_rider[rider_id]["count"] += 1
        
        cat = expense.get("category", "otros")
        if cat in by_rider[rider_id]["by_category"]:
            by_rider[rider_id]["by_category"][cat]["total"] += expense.get("amount", 0)
            by_rider[rider_id]["by_category"][cat]["count"] += 1
    
    result = sorted(by_rider.values(), key=lambda x: x["total"], reverse=True)
    
    return {
        "riders": result,
        "start_date": start_date,
        "end_date": end_date,
        "grand_total": sum(r["total"] for r in result)
    }

@api_router.get("/reports/monthly")
async def get_monthly_report(
    year: int = Query(default=datetime.now().year),
    horse_id: Optional[str] = None,
    entity_type: str = "horse",
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {
        "user_id": user_id,
        "date": {
            "$gte": f"{year}-01-01",
            "$lte": f"{year}-12-31"
        }
    }
    
    if entity_type == "horse":
        if horse_id:
            query["horse_id"] = horse_id
        expenses = await db.expenses.find(query).to_list(10000)
    else:
        if horse_id:
            query["rider_id"] = horse_id
        expenses = await db.rider_expenses.find(query).to_list(10000)
    
    monthly = {i: {"month": i, "total": 0, "count": 0} for i in range(1, 13)}
    
    for expense in expenses:
        date_str = expense.get("date", "")
        if date_str:
            try:
                month = int(date_str.split("-")[1])
                if 1 <= month <= 12:
                    monthly[month]["total"] += expense.get("amount", 0)
                    monthly[month]["count"] += 1
            except:
                pass
    
    return {
        "year": year,
        "horse_id": horse_id,
        "entity_type": entity_type,
        "months": list(monthly.values()),
        "total": sum(m["total"] for m in monthly.values())
    }

@api_router.get("/reports/horse/{horse_id}")
async def get_horse_report(
    horse_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    try:
        horse = await db.horses.find_one({"_id": ObjectId(horse_id), "user_id": user_id})
        if not horse:
            raise HTTPException(status_code=404, detail="Horse not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid horse_id")
    
    query = {"horse_id": horse_id, "user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    expenses = await db.expenses.find(query).sort("date", -1).to_list(10000)
    
    by_category = {}
    for cat in HORSE_EXPENSE_CATEGORIES:
        cat_expenses = [e for e in expenses if e.get("category") == cat]
        by_category[cat] = {
            "total": sum(e.get("amount", 0) for e in cat_expenses),
            "count": len(cat_expenses),
            "name": HORSE_CATEGORY_NAMES.get(cat, cat)
        }
    
    return {
        "horse": serialize_horse(horse),
        "total": sum(e.get("amount", 0) for e in expenses),
        "count": len(expenses),
        "by_category": by_category,
        "expenses": [serialize_expense(e) for e in expenses[:50]],
        "start_date": start_date,
        "end_date": end_date
    }

@api_router.get("/reports/rider/{rider_id}")
async def get_rider_report(
    rider_id: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    try:
        rider = await db.riders.find_one({"_id": ObjectId(rider_id), "user_id": user_id})
        if not rider:
            raise HTTPException(status_code=404, detail="Rider not found")
    except:
        raise HTTPException(status_code=400, detail="Invalid rider_id")
    
    query = {"rider_id": rider_id, "user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    expenses = await db.rider_expenses.find(query).sort("date", -1).to_list(10000)
    
    by_category = {}
    for cat in RIDER_EXPENSE_CATEGORIES:
        cat_expenses = [e for e in expenses if e.get("category") == cat]
        by_category[cat] = {
            "total": sum(e.get("amount", 0) for e in cat_expenses),
            "count": len(cat_expenses),
            "name": RIDER_CATEGORY_NAMES.get(cat, cat)
        }
    
    return {
        "rider": serialize_rider(rider),
        "total": sum(e.get("amount", 0) for e in expenses),
        "count": len(expenses),
        "by_category": by_category,
        "expenses": [serialize_rider_expense(e) for e in expenses[:50]],
        "start_date": start_date,
        "end_date": end_date
    }

@api_router.get("/reports/export")
async def export_report(
    entity_type: str = "horse",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    format: str = "csv",
    current_user: dict = Depends(get_current_user)
):
    user_id = str(current_user["_id"])
    query = {"user_id": user_id}
    if start_date or end_date:
        query["date"] = {}
        if start_date:
            query["date"]["$gte"] = start_date
        if end_date:
            query["date"]["$lte"] = end_date
    
    if entity_type == "horse":
        expenses = await db.expenses.find(query).sort("date", -1).to_list(10000)
        horses = await db.horses.find({"user_id": user_id}).to_list(1000)
        entity_map = {str(h["_id"]): h.get("name", "Unknown") for h in horses}
        id_field = "horse_id"
        category_names = HORSE_CATEGORY_NAMES
    else:
        expenses = await db.rider_expenses.find(query).sort("date", -1).to_list(10000)
        riders = await db.riders.find({"user_id": user_id}).to_list(1000)
        entity_map = {str(r["_id"]): r.get("name", "Unknown") for r in riders}
        id_field = "rider_id"
        category_names = RIDER_CATEGORY_NAMES
    
    csv_lines = ["Fecha,Entidad,Categoría,Monto,Proveedor,Descripción"]
    
    for exp in expenses:
        entity_name = entity_map.get(exp.get(id_field, ""), "Unknown")
        cat_name = category_names.get(exp.get("category", ""), exp.get("category", ""))
        line = f"{exp.get('date', '')},{entity_name},{cat_name},{exp.get('amount', 0)},{exp.get('provider', '')},{exp.get('description', '')}"
        csv_lines.append(line)
    
    return {
        "data": "\n".join(csv_lines),
        "filename": f"gastos_{entity_type}_{start_date or 'inicio'}_{end_date or 'fin'}.csv"
    }

# ==================== ADMIN ROUTES ====================

# Admin email - you can change this to your admin email
ADMIN_EMAILS = ["myhorseadmin@myhorsemanager.com", "prueba@prueba.com"]

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify admin user from JWT token"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Check if user is admin
        is_admin = user.get("is_admin", False) or user.get("email", "").lower() in [e.lower() for e in ADMIN_EMAILS]
        if not is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@api_router.get("/admin/users")
async def admin_get_all_users(
    skip: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    admin_user: dict = Depends(get_admin_user)
):
    """Get all users (admin only)"""
    query = {}
    if search:
        query["$or"] = [
            {"email": {"$regex": search, "$options": "i"}},
            {"name": {"$regex": search, "$options": "i"}}
        ]
    
    total = await db.users.count_documents(query)
    users = await db.users.find(query).skip(skip).limit(limit).to_list(limit)
    
    # Get stats for each user
    user_list = []
    for user in users:
        user_id = str(user["_id"])
        horses_count = await db.horses.count_documents({"user_id": user_id})
        riders_count = await db.riders.count_documents({"user_id": user_id})
        expenses_count = await db.expenses.count_documents({"user_id": user_id})
        
        user_list.append({
            "id": user_id,
            "email": user.get("email", ""),
            "name": user.get("name", ""),
            "language": user.get("language", "es"),
            "is_admin": user.get("is_admin", False) or user.get("email", "").lower() in [e.lower() for e in ADMIN_EMAILS],
            "created_at": user.get("created_at", "").isoformat() if user.get("created_at") else None,
            "last_login": user.get("last_login", "").isoformat() if user.get("last_login") else None,
            "stats": {
                "horses": horses_count,
                "riders": riders_count,
                "expenses": expenses_count
            }
        })
    
    return {
        "users": user_list,
        "total": total,
        "skip": skip,
        "limit": limit
    }

@api_router.get("/admin/stats")
async def admin_get_stats(admin_user: dict = Depends(get_admin_user)):
    """Get global app statistics (admin only)"""
    total_users = await db.users.count_documents({})
    total_horses = await db.horses.count_documents({})
    total_riders = await db.riders.count_documents({})
    total_expenses = await db.expenses.count_documents({})
    total_rider_expenses = await db.rider_expenses.count_documents({})
    total_competitions = await db.competitions.count_documents({})
    total_palmares = await db.palmares.count_documents({})
    total_suppliers = await db.suppliers.count_documents({})
    
    # Get recent registrations (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_users = await db.users.count_documents({"created_at": {"$gte": thirty_days_ago}})
    
    # Get total expenses amount
    pipeline = [{"$group": {"_id": None, "total": {"$sum": "$amount"}}}]
    horse_expenses_total = await db.expenses.aggregate(pipeline).to_list(1)
    rider_expenses_total = await db.rider_expenses.aggregate(pipeline).to_list(1)
    
    total_expense_amount = (
        (horse_expenses_total[0]["total"] if horse_expenses_total else 0) +
        (rider_expenses_total[0]["total"] if rider_expenses_total else 0)
    )
    
    return {
        "users": {
            "total": total_users,
            "recent": recent_users
        },
        "horses": total_horses,
        "riders": total_riders,
        "expenses": {
            "count": total_expenses + total_rider_expenses,
            "total_amount": total_expense_amount
        },
        "competitions": total_competitions,
        "palmares": total_palmares,
        "suppliers": total_suppliers
    }

@api_router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin_user: dict = Depends(get_admin_user)):
    """Delete a user and all their data (admin only)"""
    # Prevent self-deletion
    if str(admin_user["_id"]) == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account")
    
    # Check user exists
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete all user data
    await db.horses.delete_many({"user_id": user_id})
    await db.riders.delete_many({"user_id": user_id})
    await db.expenses.delete_many({"user_id": user_id})
    await db.rider_expenses.delete_many({"user_id": user_id})
    await db.competitions.delete_many({"user_id": user_id})
    await db.palmares.delete_many({"user_id": user_id})
    await db.suppliers.delete_many({"user_id": user_id})
    await db.reminders.delete_many({"user_id": user_id})
    await db.budgets.delete_many({"user_id": user_id})
    await db.horse_rider_associations.delete_many({"user_id": user_id})
    
    # Delete user
    await db.users.delete_one({"_id": ObjectId(user_id)})
    
    return {"message": "User and all associated data deleted successfully"}

@api_router.put("/admin/users/{user_id}/toggle-admin")
async def admin_toggle_admin(user_id: str, admin_user: dict = Depends(get_admin_user)):
    """Toggle admin status for a user (admin only)"""
    # Prevent self-modification
    if str(admin_user["_id"]) == user_id:
        raise HTTPException(status_code=400, detail="Cannot modify your own admin status")
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    new_admin_status = not user.get("is_admin", False)
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_admin": new_admin_status, "updated_at": datetime.utcnow()}}
    )
    
    return {"message": f"Admin status {'granted' if new_admin_status else 'revoked'}", "is_admin": new_admin_status}

@api_router.get("/admin/check")
async def admin_check(current_user: dict = Depends(get_current_user)):
    """Check if current user is admin"""
    is_admin = current_user.get("is_admin", False) or current_user.get("email", "").lower() in [e.lower() for e in ADMIN_EMAILS]
    return {"is_admin": is_admin}

# ==================== BACKUP ROUTES ====================

async def perform_automatic_backup():
    """Function to perform automatic backup - called by scheduler"""
    try:
        logging.info("Starting automatic backup at 3:00 AM...")
        backup_id = str(uuid.uuid4())
        backup_time = datetime.utcnow()
        
        collections_to_backup = [
            "users", "horses", "riders", "suppliers", "expenses", 
            "rider_expenses", "competitions", "palmares", "reminders", 
            "budgets", "horse_rider_associations"
        ]
        
        def serialize_value(value):
            if value is None:
                return None
            elif isinstance(value, ObjectId):
                return str(value)
            elif isinstance(value, datetime):
                return value.isoformat()
            elif isinstance(value, bytes):
                return None
            elif isinstance(value, list):
                return [serialize_value(item) for item in value]
            elif isinstance(value, dict):
                return {k: serialize_value(v) for k, v in value.items()}
            else:
                try:
                    import json
                    json.dumps(value)
                    return value
                except:
                    return str(value)
        
        total_size = 0
        collections_backed_up = []
        
        for collection_name in collections_to_backup:
            try:
                collection = db[collection_name]
                docs = await collection.find({}).to_list(100000)
                serialized_docs = []
                
                for doc in docs:
                    serialized_doc = {}
                    for key, value in doc.items():
                        # Limit large base64 data to prevent oversized backups
                        if key in ['photo', 'photos', 'documents', 'invoice_photos'] and value:
                            if isinstance(value, str) and len(value) > 350000:  # ~250KB in base64
                                serialized_doc[key] = "[DATA_TOO_LARGE]"
                            elif isinstance(value, list):
                                filtered_list = []
                                for item in value:
                                    if isinstance(item, str) and len(item) > 350000:
                                        filtered_list.append("[DATA_TOO_LARGE]")
                                    elif isinstance(item, dict):
                                        filtered_item = {}
                                        for k, v in item.items():
                                            if isinstance(v, str) and len(v) > 350000:
                                                filtered_item[k] = "[DATA_TOO_LARGE]"
                                            else:
                                                filtered_item[k] = serialize_value(v)
                                        filtered_list.append(filtered_item)
                                    else:
                                        filtered_list.append(serialize_value(item))
                                serialized_doc[key] = filtered_list
                            else:
                                serialized_doc[key] = serialize_value(value)
                        else:
                            serialized_doc[key] = serialize_value(value)
                    serialized_docs.append(serialized_doc)
                
                # Store each collection as a separate backup part
                part_data = {
                    "backup_id": backup_id,
                    "collection_name": collection_name,
                    "created_at": backup_time,
                    "created_by": "SYSTEM_AUTO",
                    "documents": serialized_docs,
                    "doc_count": len(serialized_docs)
                }
                
                await db.backup_parts.insert_one(part_data)
                collections_backed_up.append(collection_name)
                total_size += len(str(serialized_docs))
                
            except Exception as col_error:
                logging.error(f"Error backing up {collection_name}: {str(col_error)}")
        
        # Create backup metadata record
        backup_record = {
            "backup_id": backup_id,
            "created_at": backup_time,
            "created_by": "SYSTEM_AUTO",
            "type": "automatic",
            "collections": collections_backed_up,
            "size_mb": round(total_size / (1024 * 1024), 2)
        }
        
        await db.backups.insert_one(backup_record)
        
        # Clean up old backups (keep last 7)
        all_backups = await db.backups.find({}).sort("created_at", -1).to_list(100)
        if len(all_backups) > 7:
            old_backup_ids = [b.get("backup_id", str(b["_id"])) for b in all_backups[7:]]
            for old_id in old_backup_ids:
                await db.backup_parts.delete_many({"backup_id": old_id})
            old_mongo_ids = [b["_id"] for b in all_backups[7:]]
            await db.backups.delete_many({"_id": {"$in": old_mongo_ids}})
        
        logging.info(f"Automatic backup completed: {backup_id}, Size: {backup_record['size_mb']} MB")
        return backup_record
        
    except Exception as e:
        logging.error(f"Automatic backup failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

@api_router.post("/admin/backup")
async def create_backup(admin_user: dict = Depends(get_admin_user)):
    """Create a manual backup of the database (admin only)"""
    try:
        backup_id = str(uuid.uuid4())
        backup_time = datetime.utcnow()
        
        collections_to_backup = [
            "users", "horses", "riders", "suppliers", "expenses", 
            "rider_expenses", "competitions", "palmares", "reminders", 
            "budgets", "horse_rider_associations"
        ]
        
        def serialize_value(value):
            if value is None:
                return None
            elif isinstance(value, ObjectId):
                return str(value)
            elif isinstance(value, datetime):
                return value.isoformat()
            elif isinstance(value, bytes):
                return None
            elif isinstance(value, list):
                return [serialize_value(item) for item in value]
            elif isinstance(value, dict):
                return {k: serialize_value(v) for k, v in value.items()}
            else:
                try:
                    import json
                    json.dumps(value)
                    return value
                except:
                    return str(value)
        
        total_size = 0
        collections_backed_up = []
        
        for collection_name in collections_to_backup:
            try:
                collection = db[collection_name]
                docs = await collection.find({}).to_list(100000)
                serialized_docs = []
                
                for doc in docs:
                    serialized_doc = {}
                    for key, value in doc.items():
                        # Limit large base64 data to prevent oversized backups
                        if key in ['photo', 'photos', 'documents', 'invoice_photos'] and value:
                            if isinstance(value, str) and len(value) > 350000:
                                serialized_doc[key] = "[DATA_TOO_LARGE]"
                            elif isinstance(value, list):
                                filtered_list = []
                                for item in value:
                                    if isinstance(item, str) and len(item) > 350000:
                                        filtered_list.append("[DATA_TOO_LARGE]")
                                    elif isinstance(item, dict):
                                        filtered_item = {}
                                        for k, v in item.items():
                                            if isinstance(v, str) and len(v) > 350000:
                                                filtered_item[k] = "[DATA_TOO_LARGE]"
                                            else:
                                                filtered_item[k] = serialize_value(v)
                                        filtered_list.append(filtered_item)
                                    else:
                                        filtered_list.append(serialize_value(item))
                                serialized_doc[key] = filtered_list
                            else:
                                serialized_doc[key] = serialize_value(value)
                        else:
                            serialized_doc[key] = serialize_value(value)
                    serialized_docs.append(serialized_doc)
                
                # Store each collection as a separate backup part
                part_data = {
                    "backup_id": backup_id,
                    "collection_name": collection_name,
                    "created_at": backup_time,
                    "created_by": str(admin_user["_id"]),
                    "documents": serialized_docs,
                    "doc_count": len(serialized_docs)
                }
                
                await db.backup_parts.insert_one(part_data)
                collections_backed_up.append(collection_name)
                total_size += len(str(serialized_docs))
                
            except Exception as col_error:
                logging.error(f"Error backing up {collection_name}: {str(col_error)}")
        
        # Create backup metadata record
        backup_record = {
            "backup_id": backup_id,
            "created_at": backup_time,
            "created_by": str(admin_user["_id"]),
            "type": "manual",
            "collections": collections_backed_up,
            "size_mb": round(total_size / (1024 * 1024), 2)
        }
        
        await db.backups.insert_one(backup_record)
        
        # Clean up old backups (keep last 7)
        all_backups = await db.backups.find({}).sort("created_at", -1).to_list(100)
        if len(all_backups) > 7:
            old_backup_ids = [b.get("backup_id", str(b["_id"])) for b in all_backups[7:]]
            for old_id in old_backup_ids:
                await db.backup_parts.delete_many({"backup_id": old_id})
            old_mongo_ids = [b["_id"] for b in all_backups[7:]]
            await db.backups.delete_many({"_id": {"$in": old_mongo_ids}})
        
        return {
            "message": "Backup created successfully",
            "backup_id": backup_id,
            "created_at": backup_time.isoformat(),
            "size_mb": backup_record["size_mb"]
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Backup failed: {str(e)}")

@api_router.get("/admin/backups")
async def list_backups(admin_user: dict = Depends(get_admin_user)):
    """List all available backups (admin only)"""
    try:
        backups = await db.backups.find({}).sort("created_at", -1).to_list(7)
        return {
            "backups": [
                {
                    "id": b.get("backup_id", str(b["_id"])),
                    "created_at": b.get("created_at", datetime.utcnow()).isoformat(),
                    "size_mb": round(b.get("size_mb", 0), 2),
                    "type": b.get("type", "manual"),
                    "collections": b.get("collections", [])
                }
                for b in backups
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/admin/restore/{backup_id}")
async def restore_backup(backup_id: str, admin_user: dict = Depends(get_admin_user)):
    """Restore database from a backup (admin only) - WARNING: This will overwrite all data!"""
    try:
        # Find the backup metadata
        backup = await db.backups.find_one({"backup_id": backup_id})
        if not backup:
            # Try finding by MongoDB _id for legacy backups
            try:
                backup = await db.backups.find_one({"_id": ObjectId(backup_id)})
            except:
                pass
        
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")
        
        actual_backup_id = backup.get("backup_id", str(backup["_id"]))
        
        # Get all backup parts for this backup
        backup_parts = await db.backup_parts.find({"backup_id": actual_backup_id}).to_list(100)
        
        if not backup_parts:
            # Try legacy format (data stored directly in backup)
            if "data" in backup:
                collections_data = backup.get("data", {}).get("collections", {})
            else:
                raise HTTPException(status_code=404, detail="Backup data not found")
        else:
            collections_data = {part["collection_name"]: part["documents"] for part in backup_parts}
        
        restored_counts = {}
        
        for collection_name, docs in collections_data.items():
            if collection_name in ["backups", "backup_parts"]:
                continue
            
            if isinstance(docs, dict) and "error" in docs:
                continue
            
            collection = db[collection_name]
            
            # Clear existing data
            await collection.delete_many({})
            
            # Restore documents
            if docs and isinstance(docs, list) and len(docs) > 0:
                for doc in docs:
                    if "_id" in doc and isinstance(doc["_id"], str):
                        try:
                            doc["_id"] = ObjectId(doc["_id"])
                        except:
                            pass
                    for key in ["created_at", "updated_at"]:
                        if key in doc and isinstance(doc[key], str):
                            try:
                                doc[key] = datetime.fromisoformat(doc[key].replace('Z', '+00:00'))
                            except:
                                pass
                
                await collection.insert_many(docs)
            
            restored_counts[collection_name] = len(docs) if isinstance(docs, list) else 0
        
        return {
            "message": "Backup restored successfully",
            "backup_date": backup.get("created_at", datetime.utcnow()).isoformat(),
            "restored_collections": restored_counts
        }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Restore failed: {str(e)}")

# Include the router in the main app
# ==================== SYSTEM MONITORING ROUTES ====================

@api_router.get("/admin/system-metrics")
async def get_system_metrics(admin_user: dict = Depends(get_admin_user)):
    """Get real-time system metrics and usage statistics"""
    try:
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "database": {},
            "collections": {},
            "storage": {},
            "limits": {},
            "alerts": []
        }
        
        # Get database stats
        try:
            db_stats = await db.command("dbStats")
            storage_size_mb = db_stats.get("storageSize", 0) / (1024 * 1024)
            data_size_mb = db_stats.get("dataSize", 0) / (1024 * 1024)
            index_size_mb = db_stats.get("indexSize", 0) / (1024 * 1024)
            total_size_mb = storage_size_mb + index_size_mb
            
            # MongoDB Atlas Free Tier limit is 512 MB
            atlas_limit_mb = 512
            usage_percentage = (total_size_mb / atlas_limit_mb) * 100
            
            metrics["database"] = {
                "storage_size_mb": round(storage_size_mb, 2),
                "data_size_mb": round(data_size_mb, 2),
                "index_size_mb": round(index_size_mb, 2),
                "total_size_mb": round(total_size_mb, 2),
                "collections_count": db_stats.get("collections", 0),
                "objects_count": db_stats.get("objects", 0),
            }
            
            metrics["limits"]["mongodb_atlas"] = {
                "name": "MongoDB Atlas",
                "limit_mb": atlas_limit_mb,
                "used_mb": round(total_size_mb, 2),
                "usage_percentage": round(usage_percentage, 2),
                "status": "critical" if usage_percentage > 90 else "warning" if usage_percentage > 70 else "ok"
            }
            
            if usage_percentage > 90:
                metrics["alerts"].append({
                    "type": "critical",
                    "service": "MongoDB Atlas",
                    "message": f"Base de datos al {round(usage_percentage)}% de capacidad. ¡Acción requerida!"
                })
            elif usage_percentage > 70:
                metrics["alerts"].append({
                    "type": "warning", 
                    "service": "MongoDB Atlas",
                    "message": f"Base de datos al {round(usage_percentage)}% de capacidad. Considera limpiar datos."
                })
                
        except Exception as db_error:
            metrics["database"]["error"] = str(db_error)
        
        # Get collection-specific stats
        collections_to_check = [
            "users", "horses", "riders", "suppliers", "expenses",
            "rider_expenses", "competitions", "palmares", "reminders",
            "budgets", "backups", "backup_parts"
        ]
        
        total_documents = 0
        for col_name in collections_to_check:
            try:
                col_stats = await db.command("collStats", col_name)
                col_size_mb = col_stats.get("size", 0) / (1024 * 1024)
                doc_count = col_stats.get("count", 0)
                total_documents += doc_count
                
                metrics["collections"][col_name] = {
                    "count": doc_count,
                    "size_mb": round(col_size_mb, 2),
                    "avg_doc_size_kb": round((col_stats.get("avgObjSize", 0) / 1024), 2)
                }
            except:
                metrics["collections"][col_name] = {"count": 0, "size_mb": 0}
        
        metrics["storage"]["total_documents"] = total_documents
        
        # Get backup stats
        try:
            backup_count = await db.backups.count_documents({})
            last_backup = await db.backups.find_one({}, sort=[("created_at", -1)])
            
            metrics["storage"]["backups"] = {
                "count": backup_count,
                "last_backup": last_backup.get("created_at").isoformat() if last_backup and last_backup.get("created_at") else None,
                "last_backup_type": last_backup.get("type", "unknown") if last_backup else None
            }
        except:
            metrics["storage"]["backups"] = {"count": 0, "last_backup": None}
        
        # Railway limits (estimates based on free tier)
        metrics["limits"]["railway"] = {
            "name": "Railway",
            "description": "Servidor Backend",
            "status": "ok",
            "note": "Railway factura por uso. Monitorea tu dashboard de Railway."
        }
        
        # Expo/EAS limits
        metrics["limits"]["expo_eas"] = {
            "name": "Expo EAS",
            "description": "Builds de iOS/Android",
            "status": "ok",
            "note": "Plan gratuito: 30 builds/mes para iOS, 30 para Android"
        }
        
        return metrics
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error getting metrics: {str(e)}")

@api_router.get("/admin/usage-history")
async def get_usage_history(
    days: int = Query(default=7, ge=1, le=30),
    admin_user: dict = Depends(get_admin_user)
):
    """Get usage history for the specified number of days"""
    try:
        # Get metrics history from database
        start_date = datetime.utcnow() - timedelta(days=days)
        history = await db.metrics_history.find(
            {"timestamp": {"$gte": start_date}}
        ).sort("timestamp", 1).to_list(1000)
        
        return {
            "period_days": days,
            "history": [
                {
                    "date": h.get("timestamp").isoformat() if h.get("timestamp") else None,
                    "database_mb": h.get("database_mb", 0),
                    "documents_count": h.get("documents_count", 0),
                    "users_count": h.get("users_count", 0)
                }
                for h in history
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def collect_daily_metrics():
    """Collect and store daily metrics - called by scheduler"""
    try:
        logging.info("Collecting daily metrics...")
        
        db_stats = await db.command("dbStats")
        total_size_mb = (db_stats.get("storageSize", 0) + db_stats.get("indexSize", 0)) / (1024 * 1024)
        
        users_count = await db.users.count_documents({})
        horses_count = await db.horses.count_documents({})
        riders_count = await db.riders.count_documents({})
        
        metrics_record = {
            "timestamp": datetime.utcnow(),
            "database_mb": round(total_size_mb, 2),
            "documents_count": db_stats.get("objects", 0),
            "users_count": users_count,
            "horses_count": horses_count,
            "riders_count": riders_count
        }
        
        await db.metrics_history.insert_one(metrics_record)
        
        # Keep only last 30 days of metrics
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        await db.metrics_history.delete_many({"timestamp": {"$lt": cutoff_date}})
        
        logging.info(f"Daily metrics collected: {total_size_mb:.2f} MB used")
        return metrics_record
        
    except Exception as e:
        logging.error(f"Error collecting metrics: {str(e)}")
        return None

async def send_daily_email_report():
    """Send daily email report with metrics - called by scheduler"""
    try:
        logging.info("Sending daily email report...")
        
        # Get current metrics
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "database": {},
            "collections": {},
            "storage": {},
            "limits": {},
            "alerts": []
        }
        
        # Get database stats
        try:
            db_stats = await db.command("dbStats")
            storage_size_mb = db_stats.get("storageSize", 0) / (1024 * 1024)
            data_size_mb = db_stats.get("dataSize", 0) / (1024 * 1024)
            index_size_mb = db_stats.get("indexSize", 0) / (1024 * 1024)
            total_size_mb = storage_size_mb + index_size_mb
            
            atlas_limit_mb = 512
            usage_percentage = (total_size_mb / atlas_limit_mb) * 100
            
            metrics["database"] = {
                "storage_size_mb": round(storage_size_mb, 2),
                "data_size_mb": round(data_size_mb, 2),
                "index_size_mb": round(index_size_mb, 2),
                "total_size_mb": round(total_size_mb, 2),
            }
            
            metrics["limits"]["mongodb_atlas"] = {
                "name": "MongoDB Atlas",
                "limit_mb": atlas_limit_mb,
                "used_mb": round(total_size_mb, 2),
                "usage_percentage": round(usage_percentage, 2),
                "status": "critical" if usage_percentage > 90 else "warning" if usage_percentage > 70 else "ok"
            }
            
            if usage_percentage > 90:
                metrics["alerts"].append({
                    "type": "critical",
                    "service": "MongoDB Atlas",
                    "message": f"Base de datos al {round(usage_percentage)}% de capacidad. ¡Acción requerida!"
                })
            elif usage_percentage > 70:
                metrics["alerts"].append({
                    "type": "warning",
                    "service": "MongoDB Atlas", 
                    "message": f"Base de datos al {round(usage_percentage)}% de capacidad. Considera limpiar datos."
                })
        except Exception as e:
            logging.error(f"Error getting db stats for email: {e}")
        
        # Get collection stats
        collections_to_check = [
            "users", "horses", "riders", "suppliers", "expenses",
            "rider_expenses", "competitions", "palmares", "reminders",
            "budgets", "backups", "backup_parts"
        ]
        
        total_documents = 0
        for col_name in collections_to_check:
            try:
                col_stats = await db.command("collStats", col_name)
                metrics["collections"][col_name] = {
                    "count": col_stats.get("count", 0),
                    "size_mb": round(col_stats.get("size", 0) / (1024 * 1024), 2)
                }
                total_documents += col_stats.get("count", 0)
            except:
                metrics["collections"][col_name] = {"count": 0, "size_mb": 0}
        
        metrics["storage"]["total_documents"] = total_documents
        
        # Get last backup info
        try:
            last_backup = await db.backups.find_one({}, sort=[("created_at", -1)])
            metrics["storage"]["backups"] = {
                "count": await db.backups.count_documents({}),
                "last_backup": last_backup.get("created_at").isoformat() if last_backup and last_backup.get("created_at") else None,
                "last_backup_type": last_backup.get("type", "unknown") if last_backup else None
            }
        except:
            metrics["storage"]["backups"] = {"count": 0, "last_backup": None}
        
        # Send email
        success = send_daily_report(metrics)
        
        if success:
            logging.info("Daily email report sent successfully")
        else:
            logging.error("Failed to send daily email report")
        
        return success
        
    except Exception as e:
        logging.error(f"Error sending daily email: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

@api_router.post("/admin/send-test-email")
async def send_test_email_endpoint(admin_user: dict = Depends(get_admin_user)):
    """Send a test email with current metrics (admin only)"""
    try:
        success = await send_daily_email_report()
        if success:
            return {"message": "Email enviado correctamente", "success": True}
        else:
            raise HTTPException(status_code=500, detail="Error al enviar el email")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ==================== FILE DOWNLOAD ENDPOINT ====================

@api_router.get("/download/{filename}")
async def download_file(filename: str):
    """Download backend files for GitHub sync"""
    allowed_files = ["server.py", "email_service.py", "requirements.txt"]
    if filename not in allowed_files:
        raise HTTPException(status_code=404, detail="File not found")
    
    file_path = ROOT_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="application/octet-stream"
    )

@api_router.get("/download/frontend/{filepath:path}")
async def download_frontend_file(filepath: str):
    """Download frontend files for GitHub sync"""
    allowed_paths = [
        "app/admin.tsx",
        "app/index.tsx", 
        "app/riders.tsx",
        "app/suppliers.tsx",
        "app/expenses.tsx",
        "app/_layout.tsx",
        "app/login.tsx",
        "app/register.tsx",
        "app/forgot-password.tsx",
        "app/settings.tsx",
        "app/competitions.tsx",
        "app/palmares.tsx",
        "app/reminders.tsx",
        "app/reports.tsx",
        "src/utils/mediaUtils.ts",
        "src/utils/api.ts",
        "src/i18n/translations.ts",
        "src/i18n/index.ts",
        "src/context/AuthContext.tsx",
        "app.json",
        "package.json"
    ]
    
    if filepath not in allowed_paths:
        raise HTTPException(status_code=404, detail=f"File not allowed: {filepath}")
    
    frontend_root = Path("/app/frontend")
    file_path = frontend_root / filepath
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=str(file_path),
        filename=filepath.replace("/", "_"),
        media_type="application/octet-stream"
    )

app.include_router(api_router)

# Root endpoint for deployment health checks (required for Kubernetes)
@app.get("/")
async def root_health():
    """Root endpoint for deployment verification"""
    return {"status": "ok", "app": "My Horse Manager", "version": "v3"}

# Health check endpoint for Kubernetes
@app.get("/health")
async def health_check():
    """Health check endpoint for Kubernetes liveness/readiness probes"""
    return {"status": "healthy", "app": "My Horse Manager"}

# Favicon endpoint to prevent 404 errors
@app.get("/favicon.ico")
async def favicon():
    """Return empty response for favicon requests"""
    from fastapi.responses import Response
    return Response(content=b"", media_type="image/x-icon")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    """Start the automatic backup and metrics scheduler"""
    # Schedule automatic backup at 3:00 AM every day (Spain timezone = Europe/Madrid)
    scheduler.add_job(
        perform_automatic_backup,
        CronTrigger(hour=3, minute=0, timezone='Europe/Madrid'),
        id='daily_backup',
        name='Daily Automatic Backup at 3:00 AM',
        replace_existing=True
    )
    
    # Schedule daily metrics collection at 3:30 AM
    scheduler.add_job(
        collect_daily_metrics,
        CronTrigger(hour=3, minute=30, timezone='Europe/Madrid'),
        id='daily_metrics',
        name='Daily Metrics Collection at 3:30 AM',
        replace_existing=True
    )
    
    # Schedule daily email report at 10:00 AM
    scheduler.add_job(
        send_daily_email_report,
        CronTrigger(hour=10, minute=0, timezone='Europe/Madrid'),
        id='daily_email',
        name='Daily Email Report at 10:00 AM',
        replace_existing=True
    )
    
    scheduler.start()
    logging.info("Schedulers started - Backup: 3:00 AM, Metrics: 3:30 AM, Email: 10:00 AM (Europe/Madrid)")

@app.on_event("shutdown")
async def shutdown_db_client():
    scheduler.shutdown()
    client.close()
