from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import date, datetime, timedelta
from typing import Optional
import re

# ─────────────────────────────────────────────
#  Cấu hình
# ─────────────────────────────────────────────
SECRET_KEY = "your-secret-key-change-in-production"   # Thay bằng key bí mật thực tế
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(title="Auth API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # Chỉnh lại origin frontend thực tế
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ─────────────────────────────────────────────
#  "Database" giả lập (thay bằng DB thực tế)
# ─────────────────────────────────────────────
fake_db: dict[str, dict] = {}  # key = email hoặc mssv

# ─────────────────────────────────────────────
#  Schemas (Pydantic)
# ─────────────────────────────────────────────

KHOA = [
    "Khoa học máy tính",
    "Công nghệ phần mềm",
    "Khoa học và kỹ thuật thông tin",
    "Hệ thống thông tin",
    "Kỹ thuật máy tính",
    "Mạng máy tính và truyền thông",
]


class RegisterRequest(BaseModel):
    email: EmailStr
    mssv: str
    password: str
    confirm_password: str
    ngay_sinh: int        # 1 – 31
    thang_sinh: int       # 1 – 12
    nam_sinh: int         # ví dụ: 2003
    khoa: str

    @field_validator("mssv")
    @classmethod
    def mssv_hop_le(cls, v: str) -> str:
        if not re.fullmatch(r"\d{8}", v):
            raise ValueError("MSSV phải gồm đúng 8 chữ số")
        return v

    @field_validator("password")
    @classmethod
    def mat_khau_du_manh(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Mật khẩu phải có ít nhất 8 ký tự")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Mật khẩu phải có ít nhất 1 chữ hoa")
        if not re.search(r"\d", v):
            raise ValueError("Mật khẩu phải có ít nhất 1 chữ số")
        return v

    @field_validator("confirm_password")
    @classmethod
    def mat_khau_trung_khop(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Mật khẩu nhập lại không khớp")
        return v

    @field_validator("ngay_sinh")
    @classmethod
    def ngay_hop_le(cls, v: int) -> int:
        if not 1 <= v <= 31:
            raise ValueError("Ngày sinh phải từ 1 đến 31")
        return v

    @field_validator("thang_sinh")
    @classmethod
    def thang_hop_le(cls, v: int) -> int:
        if not 1 <= v <= 12:
            raise ValueError("Tháng sinh phải từ 1 đến 12")
        return v

    @field_validator("nam_sinh")
    @classmethod
    def nam_hop_le(cls, v: int) -> int:
        nam_hien_tai = datetime.now().year
        if not 1900 <= v <= nam_hien_tai:
            raise ValueError(f"Năm sinh phải từ 1900 đến {nam_hien_tai}")
        return v

    @field_validator("khoa")
    @classmethod
    def khoa_hop_le(cls, v: str) -> str:
        if v not in KHOA:
            raise ValueError(f"Khoa không hợp lệ. Chọn trong: {KHOA}")
        return v


class LoginRequest(BaseModel):
    email_or_mssv: str   # có thể nhập email hoặc MSSV
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class UserInfo(BaseModel):
    email: str
    mssv: str
    khoa: str
    ngay_sinh: int
    thang_sinh: int
    nam_sinh: int


# ─────────────────────────────────────────────
#  Helper functions
# ─────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email_or_mssv(identifier: str) -> Optional[dict]:
    """Tìm user theo email hoặc MSSV."""
    for user in fake_db.values():
        if user["email"] == identifier or user["mssv"] == identifier.upper():
            return user
    return None


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token không hợp lệ hoặc đã hết hạn",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = fake_db.get(email)
    if user is None:
        raise credentials_exception
    return user


# ─────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "Auth API đang chạy 🚀"}


@app.get("/auth/khoa")
def danh_sach_khoa():
    """Trả về danh sách khoa để frontend hiển thị dropdown."""
    return {"khoa": KHOA}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    # Kiểm tra email hoặc MSSV đã tồn tại chưa
    for user in fake_db.values():
        if user["email"] == data.email:
            raise HTTPException(status_code=400, detail="Email đã được đăng ký")
        if user["mssv"] == data.mssv:
            raise HTTPException(status_code=400, detail="MSSV đã được đăng ký")

    # Kiểm tra ngày sinh hợp lệ (ví dụ: 30/2 không tồn tại)
    try:
        date(data.nam_sinh, data.thang_sinh, data.ngay_sinh)
    except ValueError:
        raise HTTPException(status_code=422, detail="Ngày sinh không hợp lệ (ví dụ: 30/2 không tồn tại)")

    # Lưu user (trong thực tế: lưu vào DB)
    fake_db[data.email] = {
        "email": data.email,
        "mssv": data.mssv,
        "hashed_password": hash_password(data.password),
        "ngay_sinh": data.ngay_sinh,
        "thang_sinh": data.thang_sinh,
        "nam_sinh": data.nam_sinh,
        "khoa": data.khoa,
    }

    return {"message": f"Đăng ký thành công! Chào mừng {data.mssv}"}


@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest):
    user = get_user_by_email_or_mssv(data.email_or_mssv)
    if not user or not verify_password(data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email/MSSV hoặc mật khẩu không đúng",
        )

    token = create_access_token(
        data={"sub": user["email"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user["email"],
            "mssv": user["mssv"],
            "khoa": user["khoa"],
        },
    }


@app.get("/auth/me", response_model=UserInfo)
def get_me(current_user: dict = Depends(get_current_user)):
    """Lấy thông tin user đang đăng nhập (cần Bearer token)."""
    return UserInfo(**{k: v for k, v in current_user.items() if k != "hashed_password"})
